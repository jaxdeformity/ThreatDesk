"""Triage orchestrator, standalone threat-triage runs, not tied to an incident.

The main app has `live_orchestrator` for long-lived per-incident IC sessions.
Triage is different: it's a one-shot analyst workbench. A responder pastes
a URL/file/threat-name, the threat-triage agent researches it, produces a
markdown report + structured JSON, and exits. No multi-turn, no delegation
to other agents, no packet mutations.

Layout on disk:

    triages/
        TRG-2026-04-23-131500-abc123/
            input.json           # {triage_id, input_type, input_ref, input_text, question, siem_preference, use_environment, created_at}
            attachments/         # optional, if the user uploaded files
            report.md            # the agent's human-readable analysis
            result.json          # the agent's structured output
            events.jsonl         # append-only event log (for late SSE joiners)
            status.json          # {status: pending|running|done|error, started_at, completed_at, error}

Each triage has its own listener set so the SSE handler can stream events
to connected UIs. Late joiners replay `events.jsonl` from the beginning
before subscribing to live events.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatdesk.claude_runner import ClaudeRunner
from threatdesk import debug_logger


REPO_ROOT = Path(__file__).resolve().parent.parent
TRIAGES_DIR = Path(os.environ.get("TRIAGE_DIR", REPO_ROOT / "triages"))
AGENT_PROMPTS_DIR = REPO_ROOT / ".claude" / "agents"


# ── Per-triage live state ─────────────────────────────────────────────

@dataclass
class TriageState:
    triage_id: str
    status: str = "pending"   # pending | running | done | error
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    listeners: list[asyncio.Queue] = field(default_factory=list)


_states: dict[str, TriageState] = {}
_states_lock = asyncio.Lock()


async def _get_state(triage_id: str) -> TriageState:
    async with _states_lock:
        if triage_id not in _states:
            _states[triage_id] = TriageState(triage_id=triage_id)
        return _states[triage_id]


# ── Public API ────────────────────────────────────────────────────────

def new_triage_id(headline_hint: str | None = None) -> str:
    """Generate a new triage ID: TRG-YYYY-MM-DD-HHMMSS-<6rand>."""
    now = datetime.now(timezone.utc)
    suffix = secrets.token_hex(3)
    return f"TRG-{now.strftime('%Y-%m-%d-%H%M%S')}-{suffix}"


async def create_triage(
    *,
    input_type: str,            # "url" | "threat_name" | "text" | "file"
    input_ref: str | None,      # URL, threat name, or filename under attachments/
    input_text: str | None,     # pasted text
    question: str,              # the responder's free-form question
    siem_preference: str = "generic",
    use_environment: bool = False,
) -> dict[str, Any]:
    """Create a triage shell on disk and spawn the threat-triage run.

    Returns {"ok": bool, "triage_id": "...", "error"?: "..."}. The agent
    runs in a background task; callers should subscribe via SSE for
    progress.
    """
    triage_id = new_triage_id()
    triage_dir = TRIAGES_DIR / triage_id
    triage_dir.mkdir(parents=True, exist_ok=True)
    (triage_dir / "attachments").mkdir(exist_ok=True)

    now_iso = _now_iso()
    input_payload = {
        "triage_id": triage_id,
        "input_type": input_type,
        "input_ref": input_ref,
        "input_text": input_text,
        "question": question,
        "siem_preference": siem_preference,
        "use_environment": use_environment,
        "created_at": now_iso,
    }
    _write_json(triage_dir / "input.json", input_payload)
    _write_json(triage_dir / "status.json", {
        "status": "pending",
        "started_at": None,
        "completed_at": None,
        "error": None,
    })
    # Touch events.jsonl so the SSE handler can read it even before the
    # first event is appended.
    (triage_dir / "events.jsonl").touch()

    state = await _get_state(triage_id)
    state.status = "pending"
    state.started_at = now_iso

    debug_logger.log(
        triage_id, "triage_created",
        input_type=input_type,
        input_ref_preview=(input_ref or "")[:200],
        question_preview=(question or "")[:200],
        siem=siem_preference,
        use_environment=use_environment,
    )

    asyncio.create_task(_run_triage(triage_id))
    return {"ok": True, "triage_id": triage_id}


def list_triages() -> list[dict[str, Any]]:
    """List all triage shells on disk, newest first."""
    if not TRIAGES_DIR.exists():
        return []
    rows: list[dict[str, Any]] = []
    for d in sorted(TRIAGES_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        try:
            inp = _read_json(d / "input.json")
            status = _read_json(d / "status.json")
            result = _read_json(d / "result.json") if (d / "result.json").exists() else None
            rows.append({
                "triage_id": d.name,
                "input_type": inp.get("input_type"),
                "input_ref": inp.get("input_ref"),
                "question": inp.get("question"),
                "siem_preference": inp.get("siem_preference"),
                "use_environment": inp.get("use_environment"),
                "created_at": inp.get("created_at"),
                "custom_name": inp.get("custom_name"),
                # Which LLM produced this triage. Claude (default) or
                # the local Primus classifier. Surfaced as a badge on
                # each history row so responders can distinguish full-
                # depth runs from the lookup-shaped ones at a glance.
                "model_preference": inp.get("model_preference") or "claude",
                "status": status.get("status"),
                "started_at": status.get("started_at"),
                "completed_at": status.get("completed_at"),
                "error": status.get("error"),
                "headline": (result or {}).get("headline"),
                "severity": (result or {}).get("severity"),
                "prioritization_score": (result or {}).get("prioritization_score"),
                "exploitation_status": (result or {}).get("exploitation_status"),
            })
        except (FileNotFoundError, json.JSONDecodeError):
            continue
    return rows


def rename_triage(triage_id: str, custom_name: str | None) -> bool:
    """Update the triage's display name. Pass empty/None to clear it
    and fall back to headline/input_ref. Returns True on success,
    False if the triage doesn't exist."""
    triage_dir = TRIAGES_DIR / triage_id
    inp_path = triage_dir / "input.json"
    if not inp_path.exists():
        return False
    try:
        inp = _read_json(inp_path)
    except json.JSONDecodeError:
        return False
    name = (custom_name or "").strip()
    if name:
        inp["custom_name"] = name[:200]  # cap label length
    else:
        inp.pop("custom_name", None)
    _write_json(inp_path, inp)
    return True


def read_triage(triage_id: str) -> dict[str, Any]:
    """Read full triage state: input + status + result + report markdown + events."""
    triage_dir = TRIAGES_DIR / triage_id
    if not triage_dir.is_dir():
        raise FileNotFoundError(triage_id)
    inp = _read_json(triage_dir / "input.json")
    status = _read_json(triage_dir / "status.json")
    result = _read_json(triage_dir / "result.json") if (triage_dir / "result.json").exists() else None
    report_path = triage_dir / "report.md"
    report_md = report_path.read_text(encoding="utf-8") if report_path.exists() else None
    events = _read_events(triage_dir / "events.jsonl")
    return {
        "triage_id": triage_id,
        "input": inp,
        "status": status,
        "result": result,
        "report_md": report_md,
        "events": events,
    }


def delete_triage(triage_id: str) -> bool:
    """Remove the triage dir. Returns True if something was deleted."""
    triage_dir = TRIAGES_DIR / triage_id
    if not triage_dir.is_dir():
        return False
    import shutil
    shutil.rmtree(triage_dir, ignore_errors=True)
    return True


# ── SSE subscription ──────────────────────────────────────────────────

def subscribe(triage_id: str) -> asyncio.Queue:
    """Return a new Queue that receives this triage's live events.

    Late joiners should replay events.jsonl (via read_triage().events)
    first, then subscribe.
    """
    state = _states.get(triage_id)
    if state is None:
        state = TriageState(triage_id=triage_id)
        _states[triage_id] = state
    q: asyncio.Queue = asyncio.Queue()
    state.listeners.append(q)
    return q


def unsubscribe(triage_id: str, q: asyncio.Queue) -> None:
    state = _states.get(triage_id)
    if not state:
        return
    try:
        state.listeners.remove(q)
    except ValueError:
        pass


async def _broadcast(triage_id: str, event: dict[str, Any]) -> None:
    state = await _get_state(triage_id)
    for q in list(state.listeners):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


# ── Internal: the triage run ──────────────────────────────────────────

async def _run_triage(triage_id: str) -> None:
    """Dispatch the triage run based on the chosen model.

    input.json carries a ``model_preference`` field:
      - "claude" (default): full Opus-driven threat-triage agent run.
        Rich multi-hop research, WebFetch, web search, legal nuance,
        etc. ~5-7 min, ~$4-10 per run.
      - "primus": local 8B classifier via Ollama. Writes a lightweight
        report mechanically from the classify output. ~5s, $0. Good
        for "what's this CVE?" / bulk IOC sniff, NOT for "what
        happened in this breach?" (user-facing copy already warns).
    """
    triage_dir = TRIAGES_DIR / triage_id
    try:
        inp = _read_json(triage_dir / "input.json")
    except FileNotFoundError:
        await _mark_error(triage_id, "triage input.json missing")
        return

    model_pref = (inp.get("model_preference") or "claude").lower()
    if model_pref == "primus":
        await _run_triage_primus(triage_id, inp)
    else:
        await _run_triage_claude(triage_id, inp)


async def _run_triage_claude(triage_id: str, inp: dict[str, Any]) -> None:
    """Full Opus-driven triage, the original, high-quality path."""
    triage_dir = TRIAGES_DIR / triage_id
    state = await _get_state(triage_id)

    runner = ClaudeRunner()
    if not runner.available():
        await _mark_error(triage_id, "claude CLI not on PATH")
        return

    # Transition to running and broadcast.
    state.status = "running"
    state.started_at = _now_iso()
    _write_json(triage_dir / "status.json", {
        "status": "running",
        "started_at": state.started_at,
        "completed_at": None,
        "error": None,
    })
    await _emit(triage_id, {"kind": "triage_status", "status": "running", "ts": state.started_at, "model": "claude"})

    system_prompt = _build_system_prompt()
    user_prompt = _build_user_prompt(triage_id, inp)

    # Honor any per-agent route the operator set in Settings → AI;
    # default keeps the historic Opus-class threat-triage behavior.
    from threatdesk import ai_config
    triage_model = ai_config.resolve_model_for_agent(
        "threat-triage", fallback="claude-opus-4-7",
    )
    try:
        from threatdesk import model_policy, runtime_settings
        rt = runtime_settings.load()
        # Threat-report triage is the most likely place to trip cyber
        # safeguards; refusals retry once on the cyber-exempt model.
        async for event in model_policy.run_turn_with_fallback(
            runner,
            model=triage_model,
            fallback_model=rt.get("cyber_fallback_model", model_policy.CYBER_FALLBACK_MODEL),
            user_prompt=user_prompt,
            system_prompt_append=system_prompt,
            cwd=REPO_ROOT,
            add_dirs=[triage_dir, REPO_ROOT],
            incident_id_for_log=triage_id,
        ):
            await _emit(triage_id, event)
            if event.get("kind") == "session_complete" and not model_policy.is_refusal_event(event):
                break
            if event.get("kind") == "error":
                await _mark_error(triage_id, event.get("message", "runner error"))
                return
    except Exception as e:  # noqa: BLE001, best-effort error capture
        await _mark_error(triage_id, f"runner crashed: {e}")
        return

    # Session completed. Check for the expected output files.
    result_path = triage_dir / "result.json"
    report_path = triage_dir / "report.md"
    if not result_path.exists() and not report_path.exists():
        await _mark_error(triage_id, "agent finished but produced no report.md or result.json")
        return

    # Sanitize: the agent occasionally returns nested objects on scalar
    # chip fields (e.g. actor_group as {name, attribution_confidence,
    # tracked_alias, motivation}). Flatten to strings so the React UI
    # does not crash with "Objects are not valid as a React child".
    if result_path.exists():
        try:
            _sanitize_result_json(result_path)
        except Exception as e:  # noqa: BLE001
            # Sanitization is best-effort, never block on it.
            print(f"[triage {triage_id}] result sanitize warning: {e}")

    state.status = "done"
    state.completed_at = _now_iso()
    _write_json(triage_dir / "status.json", {
        "status": "done",
        "started_at": state.started_at,
        "completed_at": state.completed_at,
        "error": None,
    })
    await _emit(triage_id, {"kind": "triage_status", "status": "done", "ts": state.completed_at, "model": "claude"})


async def _run_triage_primus(triage_id: str, inp: dict[str, Any]) -> None:
    """Shape C of the LLM integration plan: local Primus-backed triage.

    Skips the Claude orchestrator entirely. Classifies the input text,
    writes a mechanically-synthesized report that's honest about what
    Primus can and can't do, and exits. Fast (~5s) + local + free;
    shallow + no web fetch + no legal nuance.
    """
    from threatdesk import llm_providers

    triage_dir = TRIAGES_DIR / triage_id
    state = await _get_state(triage_id)

    # Transition to running.
    state.status = "running"
    state.started_at = _now_iso()
    _write_json(triage_dir / "status.json", {
        "status": "running",
        "started_at": state.started_at,
        "completed_at": None,
        "error": None,
    })
    await _emit(triage_id, {"kind": "triage_status", "status": "running", "ts": state.started_at, "model": "primus"})

    # Probe + classify
    prov = llm_providers.get_provider("primus")
    if prov is None or not prov.available():
        await _mark_error(
            triage_id,
            "Primus provider not available. Ollama offline or model not pulled. "
            "Install Ollama + run `ollama pull hf.co/mradermacher/Llama-Primus-Merged-GGUF:Q4_K_M`, "
            "or re-submit with model_preference=claude.",
        )
        return

    # Build the text the classifier will see. Pull from all three
    # input shapes so URL / text / threat_name all work.
    classify_text = _build_primus_input(inp)
    if not classify_text.strip():
        await _mark_error(triage_id, "no classifiable content on input")
        return

    await _emit(triage_id, {
        "kind": "text", "ts": _now_iso(), "agent": "primus",
        "text": f"Classifying with {prov.status_dict().get('model')}…",
    })

    def _sync_classify():
        return prov.classify(classify_text)

    import asyncio as _asyncio
    result = await _asyncio.to_thread(_sync_classify)

    if not result.available:
        await _mark_error(triage_id, f"Primus classify failed: {result.error or 'unknown'}")
        return

    # Build a TriageResult-shaped dict the existing UI can render.
    headline = _primus_headline(inp, result)
    out = {
        "headline": headline,
        "short_answer": _primus_short_answer(result),
        "severity": _primus_severity(result),
        "prioritization_score": _primus_score(result),
        "exploitation_status": "unknown",
        "cves": [],
        "iocs": [],
        "ttps": [
            {
                "technique_id": t.get("technique_id"),
                "name": t.get("name"),
                "confidence": t.get("confidence"),
                "tactic": None,
            }
            for t in result.attack_techniques
            if isinstance(t, dict) and t.get("technique_id")
        ],
        "affected_platforms": [],
        "malware_family": (result.malware_families[0] if result.malware_families else None),
        "actor_group": (result.actor_groups[0] if result.actor_groups else None),
        "our_exposure": None,
        "hunts": [],
        "detections": [],
        "actions": [],
        "sources": [],
        "confidence": 0.5,
        "generated_by": "primus",
        "primus_elapsed_ms": result.elapsed_ms,
    }
    _write_json(triage_dir / "result.json", out)

    # Write a short, honest markdown report. No web research, no
    # recommendations. Primus can't do that. Just summarize what the
    # classifier found.
    report = _primus_report(inp, result, out)
    (triage_dir / "report.md").write_text(report, encoding="utf-8")

    # Mark done.
    state.status = "done"
    state.completed_at = _now_iso()
    _write_json(triage_dir / "status.json", {
        "status": "done",
        "started_at": state.started_at,
        "completed_at": state.completed_at,
        "error": None,
    })
    await _emit(triage_id, {
        "kind": "text", "ts": _now_iso(), "agent": "primus",
        "text": (
            f"Primus triage complete, {len(result.attack_techniques)} technique(s), "
            f"{len(result.malware_families)} family tag(s), "
            f"{len(result.actor_groups)} actor ref(s) in {result.elapsed_ms}ms."
        ),
    })
    await _emit(triage_id, {"kind": "triage_status", "status": "done", "ts": state.completed_at, "model": "primus"})


def _build_primus_input(inp: dict[str, Any]) -> str:
    """Concatenate the triage input into a single text blob for the
    classifier. Primus doesn't fetch URLs, we give it whatever text
    is already on hand."""
    parts: list[str] = []
    if inp.get("question"):
        parts.append(f"Question: {inp['question']}")
    if inp.get("input_type") == "text" and inp.get("input_text"):
        parts.append(str(inp["input_text"]))
    if inp.get("input_type") == "threat_name" and inp.get("input_ref"):
        parts.append(f"Threat name: {inp['input_ref']}")
    if inp.get("input_type") == "url" and inp.get("input_ref"):
        parts.append(f"URL (not fetched. Primus is local): {inp['input_ref']}")
    if inp.get("input_type") == "file":
        parts.append(f"File: {inp.get('input_ref') or '(uploaded)'}, classifier has no file access.")
    return "\n\n".join(parts)[:8000]


def _primus_headline(inp: dict[str, Any], result: Any) -> str:
    if inp.get("custom_name"):
        return inp["custom_name"]
    if result.malware_families:
        return f"{result.malware_families[0]}. Primus classifier"
    if inp.get("input_ref"):
        return f"{inp['input_ref']}. Primus classifier"
    return "Primus triage"


def _primus_short_answer(result: Any) -> str:
    bits = []
    if result.attack_techniques:
        tids = ", ".join(
            t.get("technique_id", "")
            for t in result.attack_techniques[:5]
            if isinstance(t, dict)
        )
        bits.append(f"ATT&CK: {tids}")
    if result.malware_families:
        bits.append(f"family: {', '.join(result.malware_families[:3])}")
    if result.cvss_estimate is not None:
        bits.append(f"est. CVSS: {result.cvss_estimate}")
    if not bits:
        return "Primus found no classifiable indicators in the input."
    return "Primus classifier output, " + "; ".join(bits) + ". Cross-verify before acting."


def _primus_severity(result: Any) -> str:
    cvss = result.cvss_estimate
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    return "informational"


def _primus_score(result: Any) -> int:
    cvss = result.cvss_estimate
    if isinstance(cvss, (int, float)):
        return max(0, min(100, int(cvss * 10)))
    # Derive a coarse score from class count when no CVSS estimate
    base = 20
    base += len(result.attack_techniques) * 4
    base += len(result.malware_families) * 6
    base += len(result.actor_groups) * 8
    return max(0, min(100, base))


def _primus_report(inp: dict[str, Any], result: Any, out: dict[str, Any]) -> str:
    lines = [
        f"# {out['headline']}",
        "",
        "> **This triage was produced by a local Primus (Llama-3.1-8B CTI) "
        "classifier via Ollama. NOT by Claude Opus.** Output is lookup-"
        "shaped only: ATT&CK/CWE/CVSS tagging from the input text. No web "
        "fetch, no multi-hop reasoning, no legal nuance, no hunt queries. "
        "Cross-verify every field before acting. For full analysis, re-run "
        "with model=Claude.",
        "",
        f"- **Classifier:** Primus (Trend Micro Llama-3.1-8B)",
        f"- **Runtime:** {result.elapsed_ms} ms",
        f"- **Confidence:** ~0.5 (classifier-only, no cross-check)",
        "",
        "## Input",
        "",
        f"- **Type:** `{inp.get('input_type')}`",
    ]
    if inp.get("input_ref"):
        lines.append(f"- **Ref:** `{inp['input_ref']}`")
    if inp.get("question"):
        lines.append(f"- **Question:** {inp['question']}")
    lines += ["", "## What Primus extracted", ""]
    if result.attack_techniques:
        lines.append("**ATT&CK techniques:**")
        for t in result.attack_techniques:
            if not isinstance(t, dict):
                continue
            tid = t.get("technique_id", "?")
            name = t.get("name", "")
            conf = t.get("confidence")
            conf_s = f" (conf {conf:.2f})" if isinstance(conf, (int, float)) else ""
            lines.append(f"- `{tid}` {name}{conf_s}")
        lines.append("")
    if result.cwes:
        lines.append(f"**CWEs:** {', '.join(result.cwes)}")
        lines.append("")
    if result.cvss_estimate is not None:
        lines.append(f"**Estimated CVSS:** {result.cvss_estimate}")
        lines.append("")
    if result.malware_families:
        lines.append(f"**Malware families:** {', '.join(result.malware_families)}")
        lines.append("")
    if result.actor_groups:
        lines.append(f"**Actor groups:** {', '.join(result.actor_groups)}")
        lines.append("")
    if not any([result.attack_techniques, result.cwes, result.cvss_estimate,
                result.malware_families, result.actor_groups]):
        lines.append("_Primus found no classifiable indicators in the input._")
        lines.append("")
    lines += [
        "## Next steps",
        "",
        "- If the extracted TTPs / families look plausible, cross-verify each",
        "  against primary sources before committing anything to an incident.",
        "- For hunt queries, detection logic, or written recommendations,",
        "  promote this triage to an incident OR re-run with model=Claude.",
        "- Raw classifier output is in `result.json` under `generated_by: primus`.",
    ]
    return "\n".join(lines) + "\n"


async def _mark_error(triage_id: str, message: str) -> None:
    triage_dir = TRIAGES_DIR / triage_id
    state = await _get_state(triage_id)
    state.status = "error"
    state.completed_at = _now_iso()
    state.error = message
    if triage_dir.is_dir():
        _write_json(triage_dir / "status.json", {
            "status": "error",
            "started_at": state.started_at,
            "completed_at": state.completed_at,
            "error": message,
        })
    await _emit(triage_id, {"kind": "triage_status", "status": "error", "error": message, "ts": state.completed_at})


async def _emit(triage_id: str, event: dict[str, Any]) -> None:
    """Persist an event to events.jsonl and broadcast to listeners."""
    triage_dir = TRIAGES_DIR / triage_id
    if triage_dir.is_dir():
        try:
            with (triage_dir / "events.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except OSError:
            pass
    await _broadcast(triage_id, event)


# ── Prompt builders ───────────────────────────────────────────────────

def _build_system_prompt() -> str:
    """Append the threat-triage agent definition. Short pointer so the
    argv doesn't blow past cmd.exe's 8191-char cap on Windows shims."""
    return (
        "You are acting as the threat-triage specialist for ThreatDesk. "
        "Read your full role definition from .claude/agents/threat-triage.md "
        "via the Read tool BEFORE doing anything else, then follow it exactly. "
        "You are in STANDALONE mode (not an incident). Your working files "
        "live under triages/<triage_id>/. Your outputs are report.md and "
        "result.json in that directory, nothing else."
    )


def _build_user_prompt(triage_id: str, inp: dict[str, Any]) -> str:
    input_type = inp.get("input_type", "text")
    siem = inp.get("siem_preference", "generic")
    use_env = inp.get("use_environment", False)
    question = (inp.get("question") or "").strip()
    ref = (inp.get("input_ref") or "").strip()

    lines = [
        f"Triage request {triage_id}. Input brief at triages/{triage_id}/input.json.",
        "",
        f"Input type: {input_type}",
    ]
    if ref:
        lines.append(f"Input ref: {ref}")
    if input_type == "file":
        lines.append(f"Attachments live at triages/{triage_id}/attachments/. Read, hash, and analyze.")
    if input_type == "text" and inp.get("input_text"):
        lines.append("Input text is included in input.json (field: input_text), read it there.")
    lines += [
        f"SIEM preference: {siem}",
        f"Use environment.json: {'yes' if use_env else 'no (skip the environment cross-reference step entirely)'}",
        "",
        "Responder's question:",
        f"  {question or '(no question, produce a general analysis and recommendations)'}",
        "",
        "Follow the workflow in .claude/agents/threat-triage.md. Write "
        f"triages/{triage_id}/report.md AND triages/{triage_id}/result.json. "
        "When both are written, emit one final line of narration and exit.",
    ]
    return "\n".join(lines)


# ── Tiny IO helpers ───────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# Scalar fields the React UI renders directly inside a chip / span.
# Any of these arriving as a dict crashes the page with React error #31.
_SCALAR_TRIAGE_FIELDS = (
    "actor_group",
    "malware_family",
    "threat_name",
    "severity",
    "exploitation_status",
    "short_answer",
)


def _flatten_scalar(v: Any) -> Any:
    """Coerce an LLM-returned object on a scalar field to a string. Prefer
    a `.name` field, fall back to `.label`, then JSON. Lists of strings
    collapse to a comma-separated string."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, dict):
        for k in ("name", "label", "value", "id"):
            if isinstance(v.get(k), str) and v[k].strip():
                # If a motivation/description rides along, append it.
                extra = v.get("motivation") or v.get("description")
                if isinstance(extra, str) and extra.strip():
                    return f"{v[k]} ({extra})"
                return v[k]
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:  # noqa: BLE001
            return str(v)
    if isinstance(v, list):
        flats = [_flatten_scalar(x) for x in v]
        return ", ".join(str(f) for f in flats if f)
    return str(v)


def _sanitize_result_json(path: Path) -> None:
    """Walk the saved result.json and flatten any object on a scalar
    field. Idempotent: stores the original object on `<field>_raw` so
    later inspection is possible. Best-effort, never raises on
    malformed input (caller ignores errors)."""
    raw = path.read_text(encoding="utf-8")
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(d, dict):
        return
    changed = False
    for key in _SCALAR_TRIAGE_FIELDS:
        if key in d and not isinstance(d[key], (str, type(None), int, float, bool)):
            d.setdefault(f"{key}_raw", d[key])
            d[key] = _flatten_scalar(d[key])
            changed = True
    if changed:
        _write_json(path, d)


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
