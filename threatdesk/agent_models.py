"""Model selection for the agents under ``.claude/agents/*.md``.

Each agent (ThreatDesk ships one: ``threat-triage``) carries its model in
a frontmatter ``model:`` line, which Claude Code reads fresh on every run.
This module is the validated lever Settings uses to change it: the next
triage uses the new model; a run already in flight keeps its model.

Writes are surgical (only the frontmatter ``model:`` line is touched,
everything else byte-preserved) and atomic (temp file + ``os.replace``).
Line endings are preserved (``newline=""``).
"""

from __future__ import annotations

import re
from pathlib import Path

from threatdesk import runtime_settings

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / ".claude" / "agents"

# Frontmatter model line, anchored per-line within the frontmatter block.
_MODEL_LINE = re.compile(r"^model:[ \t]*(.+?)[ \t]*$", re.MULTILINE)
# Agent names are file stems; constrain to avoid path traversal.
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*")


def supported_ids() -> set[str]:
    """Model ids the operator is allowed to assign (same list the UI offers)."""
    return {m["id"] for m in runtime_settings.SUPPORTED_MODELS}


def _agent_path(name: str) -> Path:
    """Resolve an agent name to its markdown file, blocking traversal."""
    if not (name and _NAME_RE.fullmatch(name)):
        raise ValueError(f"invalid agent name: {name!r}")
    path = (AGENTS_DIR / f"{name}.md").resolve()
    if path.parent != AGENTS_DIR.resolve():
        raise ValueError(f"agent path escapes agents dir: {name!r}")
    if not path.exists():
        raise FileNotFoundError(f"no such agent: {name}")
    return path


def _frontmatter_span(text: str) -> tuple[int, int] | None:
    """Return (start, end) char offsets of the frontmatter *inner* content
    (between the opening and closing ``---`` fences), or None if absent.
    """
    if not text.startswith("---"):
        return None
    try:
        first_nl = text.index("\n")
    except ValueError:
        return None
    closing = re.search(r"^---[ \t]*$", text[first_nl + 1:], re.MULTILINE)
    if not closing:
        return None
    return first_nl + 1, first_nl + 1 + closing.start()


def get_model(name: str) -> str | None:
    """Current frontmatter model for ``name``, or None if no model line."""
    text = _agent_path(name).read_text(encoding="utf-8")
    span = _frontmatter_span(text)
    region = text[span[0]:span[1]] if span else text
    m = _MODEL_LINE.search(region)
    return m.group(1).strip() if m else None


def list_agents() -> list[dict[str, str | None]]:
    """All specialists with their current model, sorted by name."""
    out: list[dict[str, str | None]] = []
    for path in sorted(AGENTS_DIR.glob("*.md")):
        out.append({"name": path.stem, "model": get_model(path.stem)})
    return out


def set_model(name: str, model: str) -> dict[str, str | None]:
    """Set one agent's frontmatter model. Returns {name, model}."""
    if model not in supported_ids():
        raise ValueError(f"unsupported model: {model!r}")
    path = _agent_path(name)
    text = path.read_text(encoding="utf-8")
    span = _frontmatter_span(text)
    if span is None:
        raise ValueError(f"{name}: no frontmatter block to edit")
    start, end = span
    inner = text[start:end]
    if _MODEL_LINE.search(inner):
        new_inner = _MODEL_LINE.sub(f"model: {model}", inner, count=1)
    else:
        # No model line yet — insert one at the end of the frontmatter.
        new_inner = inner.rstrip("\n") + f"\nmodel: {model}\n"
    if new_inner == inner:
        return {"name": name, "model": model}  # already set; no write
    new_text = text[:start] + new_inner + text[end:]
    tmp = path.with_suffix(".md.tmp")
    tmp.write_text(new_text, encoding="utf-8", newline="")
    tmp.replace(path)
    return {"name": name, "model": model}


def set_models(mapping: dict[str, str]) -> list[dict[str, str | None]]:
    """Set models for the given {name: model_id} pairs. Validates every
    name and model id *before* writing anything, so a bad entry aborts the
    whole batch rather than leaving a half-applied change.
    """
    for name, model in mapping.items():
        _agent_path(name)  # raises on bad/unknown name
        if model not in supported_ids():
            raise ValueError(f"unsupported model: {model!r}")
    for name, model in mapping.items():
        set_model(name, model)
    return list_agents()


def set_all(model: str) -> list[dict[str, str | None]]:
    """Set every specialist to ``model``."""
    if model not in supported_ids():
        raise ValueError(f"unsupported model: {model!r}")
    for path in AGENTS_DIR.glob("*.md"):
        set_model(path.stem, model)
    return list_agents()
