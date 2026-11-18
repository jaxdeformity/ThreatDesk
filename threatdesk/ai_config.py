"""AI configuration store: providers, MCP servers, agent routes.

Single source of truth for everything model-related. Customers can
swap in their own API keys, point agents at different models, and
wire MCP servers — all from the Settings UI, none of it requires
editing files.

Storage: ``config/ai_config.json`` (gitignored). Secrets (API keys,
MCP env values tagged ``"type":"secret"``) are DPAPI-encrypted before
they land on disk; the JSON wrapper itself is plaintext for
diagnosability.

Three sections:

1. ``providers`` — dict keyed by ``id`` (stable, e.g. ``anthropic``,
   ``openai``, ``ollama``, or ``custom-<slug>``). Each entry::

       {
         "kind": "anthropic" | "openai" | "ollama" |
                 "custom-openai" | "custom-anthropic",
         "label": "Anthropic",
         "endpoint": "https://api.anthropic.com",     # optional, custom-only
         "blob": "<base64-DPAPI>",                    # optional (no key for ollama)
         "fingerprint": "sk-ant-···abc1",
         "validated_at": "2026-04-29T05:33:00Z" | null,
         "last_modified": "...",
         "default_model": "claude-sonnet-4-6"          # optional hint
       }

2. ``mcp_servers`` — list of MCP server specs::

       {
         "id": "filesystem",
         "label": "Filesystem",
         "command": "npx",
         "args": ["@modelcontextprotocol/server-filesystem", "{{ROOT}}"],
         "env": {
           "GITHUB_TOKEN": {"type": "secret", "blob": "<base64-DPAPI>"},
           "ROOT_PATH":    {"type": "plain",  "value": "C:/cases"}
         },
         "enabled": true,
         "from_registry": true        # vs. user-added
       }

3. ``agent_routes`` — per-agent provider+model overrides::

       {
         "default":       {"provider": "anthropic", "model": "claude-opus-5-5"},
         "threat-triage": {"provider": "anthropic", "model": "claude-opus-5-5"}
       }
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import urllib.error
import urllib.request
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── DPAPI bindings via ctypes (no pywin32 dep) ─────────────────────

_crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
_kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(b: bytes) -> _DataBlob:
    buf = ctypes.create_string_buffer(b, len(b))
    return _DataBlob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def _bytes_from_blob(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    in_blob = _blob_from_bytes(plaintext)
    out_blob = _DataBlob()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed (GLE={_kernel32.GetLastError()})")
    try:
        return _bytes_from_blob(out_blob)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    in_blob = _blob_from_bytes(ciphertext)
    out_blob = _DataBlob()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(
            "CryptUnprotectData failed — ai_config.json was created under a "
            f"different Windows user account (GLE={_kernel32.GetLastError()}). "
            "Re-run setup to store the secret for the current user."
        )
    try:
        return _bytes_from_blob(out_blob)
    finally:
        _kernel32.LocalFree(out_blob.pbData)


def _enc_b64(plaintext: str) -> str:
    return base64.b64encode(_dpapi_encrypt(plaintext.encode("utf-8"))).decode("ascii")


def _dec_b64(blob_b64: str) -> str:
    return _dpapi_decrypt(base64.b64decode(blob_b64)).decode("utf-8")


# ─── On-disk store ──────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = _REPO_ROOT / "config" / "ai_config.json"
MCP_REGISTRY_PATH = _REPO_ROOT / "config" / "mcp-defaults.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _empty_store() -> dict[str, Any]:
    return {
        "providers": {},
        "mcp_servers": [],
        "agent_routes": {},
    }


def _read_store() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return _empty_store()
    try:
        d = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        d.setdefault("providers", {})
        d.setdefault("mcp_servers", [])
        d.setdefault("agent_routes", {})
        return d
    except (OSError, json.JSONDecodeError):
        return _empty_store()


def _write_store(d: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, CONFIG_PATH)


def _fingerprint(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return "···" + s[-4:]
    return s[:7] + "···" + s[-4:]


# ─── Providers ──────────────────────────────────────────────────────

PROVIDER_KINDS = ("anthropic", "openai", "ollama", "custom-openai", "custom-anthropic")

# Default endpoint per kind. Custom kinds require an explicit endpoint.
DEFAULT_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "ollama": "http://localhost:11434",
}


def _redact_provider(entry: dict[str, Any]) -> dict[str, Any]:
    """Public-safe view of a provider — never includes the raw key."""
    return {
        "kind": entry.get("kind"),
        "label": entry.get("label"),
        "endpoint": entry.get("endpoint"),
        "configured": bool(entry.get("blob")) or entry.get("kind") == "ollama",
        "fingerprint": entry.get("fingerprint"),
        "validated_at": entry.get("validated_at"),
        "last_modified": entry.get("last_modified"),
        "default_model": entry.get("default_model"),
    }


def list_providers() -> dict[str, dict[str, Any]]:
    store = _read_store()
    return {pid: _redact_provider(p) for pid, p in store["providers"].items()}


def get_provider_secret(provider_id: str) -> str | None:
    """Return the decrypted API key for a provider, or None if absent.
    For ``ollama`` and any provider with no stored key, returns None."""
    store = _read_store()
    entry = store["providers"].get(provider_id)
    if not entry or not entry.get("blob"):
        return None
    try:
        return _dec_b64(entry["blob"])
    except OSError:
        return None


def upsert_provider(
    provider_id: str,
    *,
    kind: str,
    label: str | None = None,
    endpoint: str | None = None,
    secret: str | None = None,
    default_model: str | None = None,
    validated: bool = False,
) -> dict[str, Any]:
    if kind not in PROVIDER_KINDS:
        raise ValueError(f"unknown provider kind: {kind}")
    store = _read_store()
    existing = store["providers"].get(provider_id, {})
    now = _now_iso()
    entry: dict[str, Any] = {
        "kind": kind,
        "label": label or existing.get("label") or kind.title(),
        "endpoint": endpoint or existing.get("endpoint") or DEFAULT_ENDPOINTS.get(kind),
        "last_modified": now,
        "validated_at": now if validated else existing.get("validated_at"),
        "default_model": default_model or existing.get("default_model"),
    }
    if secret is not None and secret.strip():
        entry["blob"] = _enc_b64(secret)
        entry["fingerprint"] = _fingerprint(secret)
    elif "blob" in existing:
        entry["blob"] = existing["blob"]
        entry["fingerprint"] = existing.get("fingerprint")
    store["providers"][provider_id] = entry
    _write_store(store)
    return _redact_provider(entry)


def delete_provider(provider_id: str) -> bool:
    store = _read_store()
    if provider_id in store["providers"]:
        store["providers"].pop(provider_id)
        # Also strip routes that reference this provider
        for agent, route in list(store["agent_routes"].items()):
            if route.get("provider") == provider_id:
                store["agent_routes"].pop(agent)
        _write_store(store)
        return True
    return False


def mark_validated(provider_id: str, ok: bool) -> None:
    store = _read_store()
    entry = store["providers"].get(provider_id)
    if entry is None:
        return
    entry["validated_at"] = _now_iso() if ok else None
    _write_store(store)


# ─── Validation ─────────────────────────────────────────────────────

def validate_provider(provider_id: str, *, timeout: float = 5.0) -> tuple[bool, str | None]:
    store = _read_store()
    entry = store["providers"].get(provider_id)
    if not entry:
        return False, "provider not found"
    kind = entry["kind"]
    endpoint = entry.get("endpoint") or DEFAULT_ENDPOINTS.get(kind, "")
    secret = get_provider_secret(provider_id)
    ok, err = _validate_kind(kind, endpoint, secret, timeout)
    mark_validated(provider_id, ok)
    return ok, err


def _validate_kind(kind: str, endpoint: str, secret: str | None, timeout: float) -> tuple[bool, str | None]:
    """Provider-specific cheap auth check."""
    try:
        if kind in ("anthropic", "custom-anthropic"):
            if not secret:
                return False, "missing API key"
            req = urllib.request.Request(
                endpoint.rstrip("/") + "/v1/models",
                headers={"x-api-key": secret, "anthropic-version": "2023-06-01"},
            )
        elif kind in ("openai", "custom-openai"):
            if not secret:
                return False, "missing API key"
            req = urllib.request.Request(
                endpoint.rstrip("/") + "/v1/models",
                headers={"Authorization": f"Bearer {secret}"},
            )
        elif kind == "ollama":
            req = urllib.request.Request(endpoint.rstrip("/") + "/api/tags")
        else:
            return False, f"unknown kind: {kind}"

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200, None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "invalid key (401)"
        if e.code == 403:
            return False, "key lacks access (403)"
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, f"network error: {e.reason}"
    except OSError as e:
        return False, f"network error: {e}"


# ─── MCP servers ────────────────────────────────────────────────────

def list_mcp_servers() -> list[dict[str, Any]]:
    store = _read_store()
    return [_redact_mcp(m) for m in store["mcp_servers"]]


def _redact_mcp(spec: dict[str, Any]) -> dict[str, Any]:
    """Public view: secret env values become {type:secret, configured:true}
    without exposing the blob."""
    env = {}
    for k, v in (spec.get("env") or {}).items():
        if isinstance(v, dict) and v.get("type") == "secret":
            env[k] = {"type": "secret", "configured": bool(v.get("blob"))}
        elif isinstance(v, dict) and v.get("type") == "plain":
            env[k] = {"type": "plain", "value": v.get("value", "")}
        else:
            env[k] = {"type": "plain", "value": str(v)}
    return {
        "id": spec.get("id"),
        "label": spec.get("label"),
        "command": spec.get("command"),
        "args": spec.get("args", []),
        "env": env,
        "enabled": bool(spec.get("enabled")),
        "from_registry": bool(spec.get("from_registry")),
    }


def upsert_mcp_server(spec: dict[str, Any]) -> dict[str, Any]:
    if not spec.get("id"):
        raise ValueError("MCP server id is required")
    if not spec.get("command"):
        raise ValueError("MCP server command is required")
    store = _read_store()
    # Encrypt any incoming env value tagged secret
    incoming_env = spec.get("env") or {}
    out_env: dict[str, Any] = {}
    existing_env: dict[str, Any] = {}
    for s in store["mcp_servers"]:
        if s["id"] == spec["id"]:
            existing_env = s.get("env") or {}
            break
    for k, v in incoming_env.items():
        if isinstance(v, dict) and v.get("type") == "secret":
            if "value" in v and v["value"]:
                out_env[k] = {"type": "secret", "blob": _enc_b64(v["value"])}
            elif "blob" in v:
                out_env[k] = {"type": "secret", "blob": v["blob"]}
            elif k in existing_env and existing_env[k].get("type") == "secret":
                out_env[k] = existing_env[k]  # preserve existing blob
            else:
                out_env[k] = {"type": "secret", "blob": ""}
        elif isinstance(v, dict) and v.get("type") == "plain":
            out_env[k] = {"type": "plain", "value": v.get("value", "")}
        else:
            out_env[k] = {"type": "plain", "value": str(v)}

    new_spec = {
        "id": spec["id"],
        "label": spec.get("label", spec["id"]),
        "command": spec["command"],
        "args": spec.get("args", []),
        "env": out_env,
        "enabled": bool(spec.get("enabled", True)),
        "from_registry": bool(spec.get("from_registry")),
    }
    # Replace by id, else append
    replaced = False
    for i, s in enumerate(store["mcp_servers"]):
        if s["id"] == new_spec["id"]:
            store["mcp_servers"][i] = new_spec
            replaced = True
            break
    if not replaced:
        store["mcp_servers"].append(new_spec)
    _write_store(store)
    return _redact_mcp(new_spec)


def delete_mcp_server(server_id: str) -> bool:
    store = _read_store()
    before = len(store["mcp_servers"])
    store["mcp_servers"] = [s for s in store["mcp_servers"] if s["id"] != server_id]
    if len(store["mcp_servers"]) != before:
        _write_store(store)
        return True
    return False


def agent_mcp_config() -> tuple[dict[str, Any], dict[str, str]]:
    """MCP servers for an agent run, split for safe hand-off.

    Returns ``(config, secret_env)``. ``config`` is a Claude Code
    ``--mcp-config`` document ({"mcpServers": {id: {command, args, env}}})
    for every enabled server, carrying only PLAIN env values, so it can be
    written to disk. ``secret_env`` holds the decrypted secret values; the
    caller puts them in the claude process environment, which the MCP
    server processes inherit. Secrets never touch the triage directory.
    """
    store = _read_store()
    servers: dict[str, Any] = {}
    secret_env: dict[str, str] = {}
    for spec in store["mcp_servers"]:
        if not spec.get("enabled", True) or not spec.get("command"):
            continue
        plain: dict[str, str] = {}
        for k, v in (spec.get("env") or {}).items():
            if isinstance(v, dict) and v.get("type") == "secret":
                if v.get("blob"):
                    try:
                        secret_env[k] = _dec_b64(v["blob"])
                    except Exception:  # noqa: BLE001 - unreadable blob: skip, server reports auth error
                        pass
            elif isinstance(v, dict):
                plain[k] = str(v.get("value", ""))
            else:
                plain[k] = str(v)
        servers[spec["id"]] = {"command": spec["command"], "args": list(spec.get("args") or []), "env": plain}
    return {"mcpServers": servers}, secret_env


def get_mcp_env_resolved(server_id: str) -> dict[str, str]:
    """Return the spawn-ready env dict for an MCP server: plain values
    pass through, secret blobs are decrypted. Used by the MCP launcher."""
    store = _read_store()
    spec = next((s for s in store["mcp_servers"] if s["id"] == server_id), None)
    if not spec:
        return {}
    out: dict[str, str] = {}
    for k, v in (spec.get("env") or {}).items():
        if isinstance(v, dict):
            if v.get("type") == "secret" and v.get("blob"):
                try:
                    out[k] = _dec_b64(v["blob"])
                except OSError:
                    pass
            elif v.get("type") == "plain":
                out[k] = v.get("value", "")
        else:
            out[k] = str(v)
    return out


def load_mcp_registry() -> list[dict[str, Any]]:
    """Catalog of safe-default MCP servers shipped with the app."""
    if not MCP_REGISTRY_PATH.exists():
        return []
    try:
        return json.loads(MCP_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


# ─── Agent routes ───────────────────────────────────────────────────

def list_agent_routes() -> dict[str, dict[str, str]]:
    return _read_store()["agent_routes"]


def set_agent_routes(routes: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """Replace the full routing dict. Validates that referenced
    providers exist (silently drops unknown ones rather than 400ing —
    UI should keep them in sync)."""
    store = _read_store()
    valid_providers = set(store["providers"].keys())
    cleaned: dict[str, dict[str, str]] = {}
    for agent_id, route in routes.items():
        if not isinstance(route, dict):
            continue
        provider = route.get("provider")
        model = route.get("model")
        if not provider or not model:
            continue
        if provider not in valid_providers and agent_id != "default":
            # default route may reference a provider that doesn't exist yet
            continue
        cleaned[agent_id] = {"provider": provider, "model": model}
    store["agent_routes"] = cleaned
    _write_store(store)
    return cleaned


def resolve_for_agent(agent_id: str) -> dict[str, str | None]:
    """Return the provider+model an agent should use. Falls back to
    'default' route, then to the first configured provider with no
    model override."""
    store = _read_store()
    routes = store["agent_routes"]
    if agent_id in routes:
        return routes[agent_id]
    if "default" in routes:
        return routes["default"]
    # Fallback: first configured provider, no model preference
    for pid, p in store["providers"].items():
        if p.get("blob") or p.get("kind") == "ollama":
            return {"provider": pid, "model": p.get("default_model")}
    return {"provider": None, "model": None}


def resolve_model_for_agent(agent_id: str, *, fallback: str | None = None) -> str | None:
    """Convenience: pull just the model string for an agent slug,
    falling back to the supplied default when no route or default
    provider yields a model. This is the entry point orchestrator
    code uses; it lets callers stay decoupled from the route shape
    and from whether ai_config is even configured (in which case
    the legacy ``runtime_settings`` fallback wins)."""
    route = resolve_for_agent(agent_id)
    model = route.get("model") if isinstance(route, dict) else None
    return model or fallback


# ─── Environment integration ────────────────────────────────────────

def load_into_environment() -> dict[str, bool]:
    """At server startup, push configured provider keys into os.environ
    so legacy callers (ANTHROPIC_API_KEY, OPENAI_API_KEY) keep working.
    Picks the default-route provider, or first configured if no default."""
    store = _read_store()
    loaded: dict[str, bool] = {"anthropic": False, "openai": False}

    for pid, entry in store["providers"].items():
        kind = entry.get("kind")
        secret = get_provider_secret(pid)
        if not secret:
            continue
        if kind in ("anthropic", "custom-anthropic"):
            if not loaded["anthropic"]:
                os.environ["ANTHROPIC_API_KEY"] = secret
                loaded["anthropic"] = True
        elif kind in ("openai", "custom-openai"):
            if not loaded["openai"]:
                os.environ["OPENAI_API_KEY"] = secret
                loaded["openai"] = True
    return loaded


# ─── Public summary ─────────────────────────────────────────────────

def public_config() -> dict[str, Any]:
    """Full status payload for /api/ai/config — never includes raw secrets."""
    return {
        "providers": list_providers(),
        "mcp_servers": list_mcp_servers(),
        "agent_routes": list_agent_routes(),
    }
