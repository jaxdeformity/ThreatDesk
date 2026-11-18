"""API keys for threat-intel / OSINT services (Settings -> Service keys).

Storage: ``config/service_keys.json`` (gitignored). Each value is
DPAPI-encrypted with the same helpers as ``ai_config`` (Windows user
scope), so the file is useless off this account. Raw keys are never
returned by the API: only configured / last-4 / source.

At startup and on every save, keys are exported to ``os.environ`` under
the service's env var. That is how the TI enrichers
(``tip_enrichers.py``) and the agents (via Bash, e.g.
``$SHODAN_API_KEY``) reach them. A key already set in the real process
environment wins over the stored one and is reported as source ``env``.

Not handled here: model providers (Anthropic / OpenAI) live in
``ai_config``; agents never receive ANTHROPIC_API_KEY (see
``claude_runner.agent_env``).
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from threatdesk import ai_config

_REPO_ROOT = Path(__file__).resolve().parent.parent
STORE_PATH = _REPO_ROOT / "config" / "service_keys.json"
_lock = threading.Lock()

# id, label, env var, what it is used for, where to get a key.
CATALOG: list[dict[str, str]] = [
    {"id": "virustotal", "label": "VirusTotal", "env": "VT_API_KEY", "category": "reputation",
     "use": "File / URL / domain / IP reputation. Used by the TIP enricher and agents.",
     "signup": "https://www.virustotal.com/gui/my-apikey"},
    {"id": "abusech", "label": "abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo)", "env": "ABUSECH_API_KEY",
     "category": "reputation", "use": "Malware hashes, C2 URLs and botnet IPs. Used by the TIP enricher.",
     "signup": "https://auth.abuse.ch/"},
    {"id": "abuseipdb", "label": "AbuseIPDB", "env": "ABUSEIPDB_API_KEY", "category": "reputation",
     "use": "IPv4 abuse reports. Used by the TIP enricher.", "signup": "https://www.abuseipdb.com/account/api"},
    {"id": "greynoise", "label": "GreyNoise", "env": "GREYNOISE_API_KEY", "category": "reputation",
     "use": "Internet-background-noise vs targeted scanning.", "signup": "https://viz.greynoise.io/account/api-key"},
    {"id": "otx", "label": "AlienVault OTX", "env": "OTX_API_KEY", "category": "reputation",
     "use": "Community pulses and IOC context.", "signup": "https://otx.alienvault.com/api"},
    {"id": "pulsedive", "label": "Pulsedive", "env": "PULSEDIVE_API_KEY", "category": "reputation",
     "use": "IOC risk scoring and feeds.", "signup": "https://pulsedive.com/api/"},
    {"id": "hybridanalysis", "label": "Hybrid Analysis", "env": "HYBRID_ANALYSIS_API_KEY", "category": "malware",
     "use": "Sandbox reports by hash.", "signup": "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab"},
    {"id": "shodan", "label": "Shodan", "env": "SHODAN_API_KEY", "category": "exposure",
     "use": "Open ports, banners and vulns for an IP.", "signup": "https://account.shodan.io/"},
    {"id": "censys", "label": "Censys", "env": "CENSYS_API_KEY", "category": "exposure",
     "use": "Host and certificate search. Store as API_ID:SECRET.", "signup": "https://search.censys.io/account/api"},
    {"id": "urlscan", "label": "urlscan.io", "env": "URLSCAN_API_KEY", "category": "web",
     "use": "Scan and search URLs, screenshots, page resources.", "signup": "https://urlscan.io/user/profile/"},
    {"id": "securitytrails", "label": "SecurityTrails", "env": "SECURITYTRAILS_API_KEY", "category": "dns",
     "use": "Passive DNS and domain history.", "signup": "https://securitytrails.com/app/account/credentials"},
    {"id": "ipinfo", "label": "IPinfo", "env": "IPINFO_TOKEN", "category": "dns",
     "use": "IP geolocation, ASN, hosting / VPN flags.", "signup": "https://ipinfo.io/account/token"},
    {"id": "wigle", "label": "WiGLE", "env": "WIGLE_API_KEY", "category": "osint",
     "use": "Wi-Fi / cell network geolocation. Store as API_NAME:API_TOKEN.", "signup": "https://wigle.net/account"},
    {"id": "hibp", "label": "Have I Been Pwned", "env": "HIBP_API_KEY", "category": "osint",
     "use": "Breach exposure for accounts / domains.", "signup": "https://haveibeenpwned.com/API/Key"},
    {"id": "nvd", "label": "NVD (NIST)", "env": "NVD_API_KEY", "category": "vuln",
     "use": "CVE detail with higher rate limits.", "signup": "https://nvd.nist.gov/developers/request-an-api-key"},
    {"id": "github", "label": "GitHub", "env": "GITHUB_TOKEN", "category": "osint",
     "use": "Code / leak search and PoC lookup (read-only token).", "signup": "https://github.com/settings/tokens"},
]
_BY_ID = {c["id"]: c for c in CATALOG}
_ENV_RX = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
# Never let this store set variables that change how agents authenticate or run.
_FORBIDDEN_ENV = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "OPENAI_API_KEY",
                  "PATH", "PYTHONPATH", "HOME", "USERPROFILE", "APPDATA", "SOC_AGENT_BILLING"}

# Names HoneyHive (and `Name: key` notes) use -> our ids.
ALIASES = {"vt": "virustotal", "virustotal": "virustotal", "abuseipdb": "abuseipdb", "greynoise": "greynoise",
           "shodan": "shodan", "urlscan": "urlscan", "wigle": "wigle", "otx": "otx", "alienvault": "otx",
           "abusech": "abusech", "abuse.ch": "abusech", "censys": "censys", "securitytrails": "securitytrails",
           "ipinfo": "ipinfo", "hibp": "hibp", "pulsedive": "pulsedive", "hybridanalysis": "hybridanalysis",
           "nvd": "nvd", "github": "github"}

# Env vars that were in the real environment before we exported anything.
_ORIGINAL_ENV = {c["env"] for c in CATALOG if os.environ.get(c["env"])}


def _read() -> dict[str, Any]:
    try:
        data = json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault("keys", {})
    data.setdefault("custom", {})
    return data


def _write(data: dict[str, Any]) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, STORE_PATH)


def _entry(sid: str, data: dict[str, Any]) -> dict[str, str] | None:
    return _BY_ID.get(sid) or data["custom"].get(sid)


def _secret(sid: str, data: dict[str, Any]) -> str:
    blob = (data["keys"].get(sid) or {}).get("blob")
    if not blob:
        return ""
    try:
        return ai_config._dec_b64(blob)
    except Exception:  # noqa: BLE001 - unreadable blob (other user / machine)
        return ""


def list_keys() -> list[dict[str, Any]]:
    """Catalog + custom entries with status. Never includes the key."""
    with _lock:
        data = _read()
    out = []
    for e in CATALOG + list(data["custom"].values()):
        sid = e["id"]
        stored = data["keys"].get(sid) or {}
        from_env = e["env"] in _ORIGINAL_ENV
        out.append({
            **e, "custom": sid in data["custom"],
            "configured": bool(stored.get("blob")) or from_env,
            "source": "env" if from_env else ("settings" if stored.get("blob") else None),
            "last4": stored.get("last4"), "updated_at": stored.get("updated_at"),
        })
    return out


def set_key(sid: str, value: str) -> dict[str, Any]:
    value = (value or "").strip()
    with _lock:
        data = _read()
        e = _entry(sid, data)
        if e is None:
            raise KeyError(sid)
        if not value:
            data["keys"].pop(sid, None)
            if e["env"] not in _ORIGINAL_ENV:
                os.environ.pop(e["env"], None)
        else:
            from datetime import datetime, timezone
            data["keys"][sid] = {"blob": ai_config._enc_b64(value), "last4": value[-4:],
                                 "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            if e["env"] not in _ORIGINAL_ENV:
                os.environ[e["env"]] = value
        _write(data)
    return next(k for k in list_keys() if k["id"] == sid)


def add_custom(sid: str, label: str, env: str, use: str = "", signup: str = "") -> dict[str, Any]:
    sid = re.sub(r"[^a-z0-9_-]", "", (sid or "").lower())[:40]
    env = (env or "").strip().upper()
    if not sid or sid in _BY_ID:
        raise ValueError("id must be new, lowercase letters/digits/-/_")
    if not _ENV_RX.match(env) or env in _FORBIDDEN_ENV:
        raise ValueError(f"env var {env!r} not allowed (A-Z0-9_, not a reserved name)")
    with _lock:
        data = _read()
        data["custom"][sid] = {"id": sid, "label": label or sid, "env": env, "category": "custom",
                               "use": use, "signup": signup}
        _write(data)
    return next(k for k in list_keys() if k["id"] == sid)


def delete_custom(sid: str) -> None:
    with _lock:
        data = _read()
        e = data["custom"].pop(sid, None)
        data["keys"].pop(sid, None)
        _write(data)
    if e and e["env"] not in _ORIGINAL_ENV:
        os.environ.pop(e["env"], None)


def load_into_environment() -> list[str]:
    """Export stored keys to os.environ (real env vars win). Returns ids."""
    with _lock:
        data = _read()
    loaded = []
    for sid in data["keys"]:
        e = _entry(sid, data)
        if not e or e["env"] in _ORIGINAL_ENV:
            continue
        v = _secret(sid, data)
        if v:
            os.environ[e["env"]] = v
            loaded.append(sid)
    return loaded


def import_file(path: Path) -> list[str]:
    """Import from a HoneyHive ``data/secrets.json`` (flat {name: key}) or a
    ``Name: key`` notes file. Fills only keys that are not set. Returns ids."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    pairs: list[tuple[str, str]] = []
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            pairs = [(str(k), str(v)) for k, v in obj.items() if isinstance(v, str)]
    except json.JSONDecodeError:
        for line in text.splitlines():
            m = re.match(r"\s*([A-Za-z][\w. ]*?)\s*[:=]\s*(\S+)\s*$", line)
            if m:
                pairs.append((m.group(1), m.group(2)))
    current = {k["id"]: k["configured"] for k in list_keys()}
    imported = []
    for name, val in pairs:
        sid = ALIASES.get(name.strip().lower().replace(" ", ""))
        if sid and val and not current.get(sid):
            set_key(sid, val)
            imported.append(sid)
    return imported
