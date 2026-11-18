"""In-app runtime settings for ThreatDesk (models, billing mode).

File: config/runtime-settings.json (gitignored). Read when a triage
starts, so a change applies to the next triage, never to one in flight.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatdesk.model_policy import (  # noqa: E402
    SUPPORTED_MODELS,
    CYBER_FALLBACK_MODEL,
    DEFAULT_TRIAGE_MODEL,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = REPO_ROOT / "config" / "runtime-settings.json"

DEFAULTS: dict[str, Any] = {
    # Model the threat-triage agent runs on (unless Settings -> AI routes it).
    "triage_model": DEFAULT_TRIAGE_MODEL,
    # On a cyber-safeguard refusal, retry the turn once on this model.
    # Off by default: only useful where the operator's account holds a
    # cyber-use exemption for the fallback model.
    "cyber_fallback_enabled": False,
    "cyber_fallback_model": CYBER_FALLBACK_MODEL,
    # False: agents use ANTHROPIC_API_KEY (or Bedrock/Vertex env) when set.
    # True: agents get a blank API key and run on the logged-in Claude
    # subscription (demo machines).
    "use_subscription": False,
    # Agent turn backend: "cli" = one `claude -p` per triage.
    "runner_backend": "cli",
}


def load() -> dict[str, Any]:
    settings = dict(DEFAULTS)
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k in DEFAULTS:
                    if k in data:
                        settings[k] = data[k]
        except (OSError, json.JSONDecodeError):
            pass
    return settings


def save(partial: dict[str, Any]) -> dict[str, Any]:
    cur = load()
    for k, v in partial.items():
        if k in DEFAULTS:
            cur[k] = v
    ids = {m["id"] for m in SUPPORTED_MODELS}
    for key in ("triage_model", "cyber_fallback_model"):
        if cur[key] not in ids:
            cur[key] = DEFAULTS[key]
    cur["cyber_fallback_enabled"] = bool(cur["cyber_fallback_enabled"])
    cur["use_subscription"] = bool(cur["use_subscription"])
    if cur.get("runner_backend") not in ("sdk", "cli"):
        cur["runner_backend"] = DEFAULTS["runner_backend"]
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_PATH)
    return cur
