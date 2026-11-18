"""Minimal .env loader (no dependency).

The server reads API keys from the environment only. This loads
``<repo>/.env`` at startup for variables that are not already set, so a
key exported in the shell always wins over the file. ``.env`` is
gitignored; never commit it.
"""

from __future__ import annotations

import os
from pathlib import Path

# Only these are loaded. ANTHROPIC_* never come from .env: set the key in
# Settings -> AI (DPAPI store) or in the real OS environment.
def _service_key_envs() -> frozenset[str]:
    """Threat-intel / OSINT key env vars (Settings -> Service keys catalog)."""
    try:
        from threatdesk.service_keys import CATALOG
        return frozenset(c["env"] for c in CATALOG)
    except Exception:  # noqa: BLE001 - never block import on the catalog
        return frozenset()


# THREATDESK_INVENTORY / THREATDESK_TECH_STACK(_CSV): the org technology
# inventory (SOC_ORG_* names accepted for compatibility).
DEFAULT_ALLOW = frozenset({"OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL", "SOC_ORG_TECH_STACK", "SOC_ORG_INVENTORY",
                           "THREATDESK_TECH_STACK", "THREATDESK_INVENTORY", "THREATDESK_TECH_STACK_CSV",
                           "THREATDESK_PORT", "NVD_API_KEY"}) | _service_key_envs()


def load(path: Path | None = None, allow: frozenset[str] | set[str] = DEFAULT_ALLOW) -> list[str]:
    """Set unset/empty allowlisted env vars from ``path``. Returns the names set (never values)."""
    target = path or (Path(__file__).resolve().parent.parent / ".env")
    try:
        text = target.read_text(encoding="utf-8")
    except OSError:
        return []
    loaded: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if not key or not value or key not in allow:
            continue
        if os.environ.get(key):
            continue
        os.environ[key] = value
        loaded.append(key)
    return loaded
