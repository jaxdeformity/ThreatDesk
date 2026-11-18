"""Model catalogue, role defaults, and the cyber-guardrail fallback.

Every triage turn goes through ``run_turn_with_fallback``.
If the primary model refuses the turn (Anthropic usage-policy / cyber
safeguard refusal) and a fallback is configured (runtime setting
``cyber_fallback_enabled``), the same prompt is retried once on the
fallback model. Otherwise a ``refusal_unresolved`` event is emitted.

Refusal signals we act on (anything else is treated as a normal turn):
- ``kind == "refusal"``, emitted by the runner when the API returns
  ``stop_reason: "refusal"``.
- An ``error`` / ``session_complete`` / ``text`` event whose text is the
  CLI's own refusal banner ("API Error: ... Usage Policy ..."). Plain
  model prose that merely mentions a usage policy does NOT match: the
  patterns require the CLI's "API Error" framing.
"""

from __future__ import annotations

import re
from typing import Any, AsyncIterator

# Optional refusal fallback. Off by default (runtime_settings.cyber_fallback_enabled);
# only useful where the operator's account holds a cyber-use exemption for it.
CYBER_FALLBACK_MODEL = "claude-opus-4-7"

DEFAULT_TRIAGE_MODEL = "claude-opus-5-5"


SUPPORTED_MODELS: list[dict[str, str]] = [
    {
        "id": "claude-fable-5-2",
        "label": "Fable 5.2",
        "tag": "horsepower",
        "notes": "Strongest reasoning. $8/$40 per MTok. ",
    },
    {
        "id": "claude-opus-5-5",
        "label": "Opus 5.5",
        "tag": "horsepower",
        "notes": "Deep reasoning at half Fable's price ($4/$20). Default for threat triage.",
    },
    {
        "id": "claude-sonnet-5-5",
        "label": "Sonnet 5.5",
        "tag": "balanced",
        "notes": "Balanced ($2/$10). ",
    },
    {
        "id": "claude-haiku-5-5",
        "label": "Haiku 5.5",
        "tag": "cheap",
        "notes": "Cheapest and fastest ($0.10/$0.50 under 100K). ",
    },
    {
        "id": CYBER_FALLBACK_MODEL,
        "label": "Opus 4.7 (cyber-exempt)",
        "tag": "fallback",
        "notes": "Cyber-use exemption. Used automatically for one turn when another model refuses.",
    },
]

SUPPORTED_IDS = frozenset(m["id"] for m in SUPPORTED_MODELS)

_REFUSAL_PATTERNS = [
    re.compile(r"API Error[^\n]{0,200}(Usage Policy|unable to respond to this request)", re.I),
    re.compile(r"appears to violate our Usage Policy", re.I),
    re.compile(r"\bstop_reason\b[\"':\s]+refusal", re.I),
]


def _event_text(ev: dict[str, Any]) -> str:
    for key in ("message", "result", "text"):
        v = ev.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def is_refusal_event(ev: dict[str, Any]) -> bool:
    kind = ev.get("kind")
    if kind == "refusal":
        return True
    if kind not in ("error", "session_complete", "text"):
        return False
    text = _event_text(ev)
    if not text:
        return False
    return any(p.search(text) for p in _REFUSAL_PATTERNS)


async def run_turn_with_fallback(
    runner: Any,
    *,
    model: str,
    fallback_model: str | None = CYBER_FALLBACK_MODEL,
    **kwargs: Any,
) -> AsyncIterator[dict[str, Any]]:
    """Run one turn on ``model``; on refusal, retry once on ``fallback_model``.

    Yields every event from the primary attempt up to and including the
    refusal, then a ``model_fallback`` event, then the fallback's events.
    If the fallback also refuses, a ``refusal_unresolved`` event is
    yielded so the operator sees it rather than a silent stall.
    """
    refused = False
    side_effects: list[str] = []
    agen = runner.run_turn(model=model, **kwargs)
    try:
        async for ev in agen:
            yield ev
            if ev.get("kind") == "tool_call":
                side_effects.append(str(ev.get("input_preview") or ev.get("tool_name") or "tool call"))
            if is_refusal_event(ev):
                refused = True
                break
    finally:
        await agen.aclose()

    if not refused:
        return
    if not fallback_model or fallback_model == model:
        yield {"kind": "refusal_unresolved", "model": model,
               "message": f"{model} refused and no distinct fallback model is configured."}
        return

    yield {
        "kind": "model_fallback",
        "from_model": model,
        "to_model": fallback_model,
        "message": f"{model} refused this turn; retrying once on {fallback_model}. "
                   f"Next turn returns to {model}.",
    }
    retry_kwargs = dict(kwargs)
    if side_effects and isinstance(retry_kwargs.get("user_prompt"), str):
        # The refused attempt may already have written triage files . Replaying blind would duplicate those writes.
        done = "\n".join(f"- {s[:200]}" for s in side_effects[:25])
        retry_kwargs["user_prompt"] = (
            "NOTE: a previous attempt at this turn (another model) was refused partway. It already "
            "executed these tool calls; do NOT repeat them. Check the files already written in the triage directory before writing:\n"
            f"{done}\n\n" + retry_kwargs["user_prompt"]
        )
    refused_again = False
    agen2 = runner.run_turn(model=fallback_model, **retry_kwargs)
    try:
        async for ev in agen2:
            yield ev
            if is_refusal_event(ev):
                refused_again = True
                break
    finally:
        await agen2.aclose()
    if refused_again:
        yield {"kind": "refusal_unresolved", "model": fallback_model,
               "message": f"Both {model} and {fallback_model} refused. Rephrase or narrow the request."}
