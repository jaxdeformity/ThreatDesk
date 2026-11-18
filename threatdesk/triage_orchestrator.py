"""Triage orchestrator, standalone threat-triage runs, not tied to an incident.

Triage is a one-shot analyst workbench. A responder pastes
a URL/file/threat-name, the threat-triage agent researches it, produces a
markdown report + structured JSON, and exits. No multi-turn, no delegation
to other agents.

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
import re
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
    """Run the threat-triage agent for one triage (Claude only)."""
    triage_dir = TRIAGES_DIR / triage_id
    try:
        inp = _read_json(triage_dir / "input.json")
    except FileNotFoundError:
        await _mark_error(triage_id, "triage input.json missing")
        return
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

    from threatdesk import ai_config, model_policy, runtime_settings
    rt = runtime_settings.load()
    # A per-agent route set in Settings -> AI wins; else the runtime default.
    triage_model = ai_config.resolve_model_for_agent(
        "threat-triage", fallback=rt.get("triage_model", model_policy.DEFAULT_TRIAGE_MODEL),
    )
    # Refusal fallback is opt-in (cyber_fallback_enabled); None = no retry.
    fallback_model = rt.get("cyber_fallback_model") if rt.get("cyber_fallback_enabled") else None
    try:
        async for event in model_policy.run_turn_with_fallback(
            runner,
            model=triage_model,
            fallback_model=fallback_model,
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
        "Your working files "
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
        f"Use environment: {'yes, GET http://127.0.0.1:' + _port() + '/api/environment (org profile + inventory)' if use_env else 'no (skip the environment cross-reference step entirely)'}",
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

def _port() -> str:
    return os.environ.get("THREATDESK_PORT", "8444").strip() or "8444"


def safe_attachment_name(name: str) -> str:
    """Basename only, so an uploaded filename can never leave attachments/."""
    base = (name or "").replace("\\", "/").split("/")[-1].strip()
    base = base.lstrip(".") if set(base) <= {"."} else base
    return base or "upload.bin"


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
