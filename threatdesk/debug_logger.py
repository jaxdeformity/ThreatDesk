"""Structured JSONL debug logger for triage runs.

Each triage gets ``logs/<triage_id>.jsonl``: one JSON line per
noteworthy event (``triage_created``, ``subprocess_spawned`` with the
sanitized claude argv, ``subprocess_event``, ``subprocess_exited`` with
exit code + stderr tail, errors with traceback). Grep-friendly and
tailable.

Secrets are scrubbed: any env var name containing KEY|TOKEN|SECRET is
redacted, and the ``--append-system-prompt`` value is truncated to the
first 200 chars.

Also mirrors to stderr when ``THREATDESK_DEBUG=1``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = Path(os.environ.get("THREATDESK_LOG_DIR", REPO_ROOT / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

_MIRROR_TO_STDERR = os.environ.get("THREATDESK_DEBUG", "").lower() in ("1", "true", "yes")

# Serialize writes per-file so concurrent event emitters don't interleave
# half-lines. Per-log lock keyed by log_id.
_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()


def _lock_for(log_id: str) -> threading.Lock:
    with _locks_lock:
        lk = _locks.get(log_id)
        if lk is None:
            lk = threading.Lock()
            _locks[log_id] = lk
        return lk


def _log_path(log_id: str) -> Path:
    # Keep it simple: one file per triage, lifetime of the triage.
    # Collisions would require the same triage id to exist twice
    # (the ID contains a timestamp + title slug, so basically never).
    safe = log_id.replace("/", "_").replace("\\", "_")
    return LOG_DIR / f"{safe}.jsonl"


def log(log_id: str, kind: str, **fields: Any) -> None:
    """Write one line of structured JSON to the per-triage log file.

    ``kind`` is the event discriminator. Additional fields are merged
    into the record. ``ts`` is added automatically.
    """
    if not log_id:
        return
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "log_id": log_id,
        "kind": kind,
    }
    record.update(_sanitize(fields))
    line = json.dumps(record, default=str, ensure_ascii=False)
    path = _log_path(log_id)
    try:
        with _lock_for(log_id):
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError as e:
        # Best-effort logging, never crash the caller.
        sys.stderr.write(f"[debug_logger] write failed: {e}\n")
    if _MIRROR_TO_STDERR:
        sys.stderr.write("[threatdesk] " + line + "\n")
        sys.stderr.flush()


def log_exception(log_id: str, where: str) -> None:
    """Capture the current exception as an ``error`` log entry."""
    log(
        log_id,
        "error",
        where=where,
        exc=traceback.format_exc(),
    )


def read_log(log_id: str, tail: int | None = None) -> list[dict[str, Any]]:
    """Read (up to ``tail`` most recent) log entries for a triage.

    Returns a list of parsed JSON objects. Malformed lines are skipped
    with a ``_malformed`` entry in their place so we don't silently drop
    diagnostic context.
    """
    path = _log_path(log_id)
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"_malformed": True, "raw": line[:400]})
    if tail is not None and tail > 0:
        out = out[-tail:]
    return out


def list_log_files() -> list[dict[str, Any]]:
    """Return a summary of every ``<triage>.jsonl`` file on disk.

    For ad-hoc inspection of past triage runs.
    """
    out: list[dict[str, Any]] = []
    if not LOG_DIR.exists():
        return out
    for p in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            stat = p.stat()
        except OSError:
            continue
        out.append({
            "log_id": p.stem,
            "path": str(p),
            "size_bytes": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        })
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


# ── Sanitization ──────────────────────────────────────────────────────

_SECRET_KEY_SUBSTRINGS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "CREDENTIAL")


def _sanitize(obj: Any) -> Any:
    """Recursively scrub obvious secrets from a structure.

    Rules:
    - dict keys whose name contains KEY / TOKEN / SECRET / PASSWORD → value
      replaced with "[REDACTED]"
    - ``--append-system-prompt`` values (in argv lists) truncated at 200 chars
    - strings longer than 4096 chars truncated with an ellipsis + original length
    """
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _looks_secret(str(k)) else _sanitize(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return _sanitize_list(obj)
    if isinstance(obj, str):
        if len(obj) > 4096:
            return obj[:4096] + f"…[truncated, original len {len(obj)}]"
        return obj
    return obj


def _sanitize_list(lst: list[Any]) -> list[Any]:
    out: list[Any] = []
    i = 0
    while i < len(lst):
        item = lst[i]
        # argv-style truncation for --append-system-prompt
        if isinstance(item, str) and item == "--append-system-prompt" and i + 1 < len(lst):
            out.append(item)
            val = lst[i + 1]
            if isinstance(val, str) and len(val) > 200:
                out.append(val[:200] + f"…[+{len(val) - 200} chars]")
            else:
                out.append(_sanitize(val))
            i += 2
            continue
        out.append(_sanitize(item))
        i += 1
    return out


def _looks_secret(key: str) -> bool:
    up = key.upper()
    return any(s in up for s in _SECRET_KEY_SUBSTRINGS)
