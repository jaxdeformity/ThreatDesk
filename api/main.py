"""ThreatDesk API: threat triage, vulnerabilities, threat feed, TIP, settings.

Local-only, single machine. Serves the built UI from ``web-dist/``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from threatdesk import envfile as _envfile

_envfile.load()

from threatdesk import agent_models  # noqa: E402
from threatdesk import ai_config  # noqa: E402
from threatdesk import inventory  # noqa: E402
from threatdesk import runtime_settings as rt_settings  # noqa: E402
from threatdesk import service_keys  # noqa: E402
from threatdesk import threat_feed  # noqa: E402
from threatdesk import tip_catalog  # noqa: E402
from threatdesk import tip_enrichers  # noqa: E402
from threatdesk import tip_misp  # noqa: E402
from threatdesk import triage_orchestrator  # noqa: E402

try:
    ai_config.load_into_environment()
    service_keys.load_into_environment()
except Exception as _e:  # noqa: BLE001 - never block startup on the key store
    logging.getLogger(__name__).warning("key store load skipped: %s", _e)

# ─── Paths ────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_DIST_DIR = Path(os.environ.get("THREATDESK_WEB_DIST", REPO_ROOT / "web-dist"))
PORT = int(os.environ.get("THREATDESK_PORT", "8444") or 8444)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_streaming(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


# ─── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatDesk",
    description="Threat triage + vulnerability dashboard. Local-only; never expose to network.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "product": "ThreatDesk", "version": "0.1.0"}


# ─── Environment profile (org, SIEM, crown jewels) + inventory ───────

ENV_CONFIG_PATH = REPO_ROOT / "config" / "environment.json"
ENV_EXAMPLE_PATH = REPO_ROOT / "config" / "environment.example.json"


@app.get("/api/environment")
async def get_environment() -> dict[str, Any]:
    """Return the responder's environment inventory (OS fleet, EDR,
    crown jewels, regulatory scope, etc.) plus the org inventory, used by the threat-triage
    agent to contextualize external threat reports to this org.

    Serves ``config/environment.json`` if it exists, otherwise falls
    back to ``config/environment.example.json`` with a ``source``
    marker so the UI can warn about stock data.
    """
    path = ENV_CONFIG_PATH if ENV_CONFIG_PATH.exists() else ENV_EXAMPLE_PATH
    if not path.exists():
        return {
            "environment": None,
            "inventory": inventory.load_assets(),
            "source": "missing",
            "message": "No environment config found. Copy environment.example.json to environment.json and edit.",
        }
    try:
        env = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=500, detail=f"couldn't parse {path.name}: {e}")
    return {
        "environment": env,
        "source": "custom" if path == ENV_CONFIG_PATH else "example",
        "path": str(path),
        # The org technology inventory: the one asset list (tech-stack CSV >
        # inventory JSON > env list). The triage agent reads it from here.
        "inventory": inventory.load_assets(),
    }


class EnvironmentUpdateRequest(BaseModel):
    environment: dict[str, Any]


@app.post("/api/environment")
async def put_environment(req: EnvironmentUpdateRequest) -> dict[str, Any]:
    """Overwrite ``config/environment.json`` with the provided payload.
    This is how the UI edits the inventory; agents read-only via GET.
    """
    ENV_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = ENV_CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(req.environment, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, ENV_CONFIG_PATH)
    return {"ok": True, "path": str(ENV_CONFIG_PATH), "source": "custom"}


# ─── Velociraptor / RTR ───────────────────────────────────────────────

class RuntimeSettingsPayload(BaseModel):
    triage_model: str | None = None
    cyber_fallback_enabled: bool | None = None
    cyber_fallback_model: str | None = None
    use_subscription: bool | None = None
    runner_backend: str | None = Field(None, pattern="^(sdk|cli)$")


@app.get("/api/settings/runtime")
async def get_runtime_settings() -> dict[str, Any]:
    return {
        "settings": rt_settings.load(),
        "supported_models": rt_settings.SUPPORTED_MODELS,
    }


@app.post("/api/settings/runtime")
async def save_runtime_settings(req: RuntimeSettingsPayload) -> dict[str, Any]:
    partial = {k: v for k, v in req.model_dump().items() if v is not None}
    new = rt_settings.save(partial)
    return {"ok": True, "settings": new}



# ─── AI config (providers, MCP servers, agent routing) ───────────────
#
# All configuration around which model serves which agent lives here.
# Ships with an empty store; fill it in via Settings → AI.


# Agent slugs the Settings -> AI routing UI offers.
CANONICAL_AGENTS_FOR_ROUTING: list[dict[str, str]] = [
    {"slug": "default",       "label": "Default (fallback)", "kind": "system"},
    {"slug": "threat-triage", "label": "Threat Triage",      "kind": "agent"},
]


class ProviderUpsertPayload(BaseModel):
    id: str
    kind: str
    label: str | None = None
    endpoint: str | None = None
    secret: str | None = None
    default_model: str | None = None
    validate: bool = True


class McpEnvValue(BaseModel):
    type: str
    value: str | None = None


class McpUpsertPayload(BaseModel):
    id: str
    label: str | None = None
    command: str
    args: list[str] = []
    env: dict[str, McpEnvValue] = {}
    enabled: bool = True
    from_registry: bool = False


class RoutesPayload(BaseModel):
    routes: dict[str, dict[str, str]]


@app.get("/api/ai/config")
async def get_ai_config() -> dict[str, Any]:
    """Full AI config snapshot. Never includes raw secrets — only
    fingerprints and configured-or-not flags. Also includes the
    safe-default MCP registry and canonical agents list so the UI
    has a single source of truth."""
    return {
        "providers": ai_config.list_providers(),
        "mcp_servers": ai_config.list_mcp_servers(),
        "agent_routes": ai_config.list_agent_routes(),
        "mcp_registry": ai_config.load_mcp_registry(),
        "canonical_agents": CANONICAL_AGENTS_FOR_ROUTING,
        "supported_models": rt_settings.SUPPORTED_MODELS,
    }


# ─── Specialist agent models (frontmatter, read per Task spawn) ────────
# Unlike the coordinator/Scribe knob above, these live in each agent's
# .claude/agents/*.md frontmatter, which Claude Code re-reads on every
# Task spawn — so a change here applies to the next specialist spawn with
# no server reboot. Same flap-free semantics: in-flight subprocesses keep
# the model they launched with.


class AgentModelsPayload(BaseModel):
    all: str | None = None              # set every specialist to this model id
    models: dict[str, str] | None = None  # per-agent {name: model_id}


@app.get("/api/settings/agents")
async def get_agent_models() -> dict[str, Any]:
    return {
        "agents": agent_models.list_agents(),
        "supported_models": rt_settings.SUPPORTED_MODELS,
    }


@app.post("/api/ai/providers")
async def upsert_ai_provider(req: ProviderUpsertPayload) -> dict[str, Any]:
    if req.kind not in ai_config.PROVIDER_KINDS:
        raise HTTPException(400, f"unknown provider kind: {req.kind}")
    redacted = ai_config.upsert_provider(
        req.id,
        kind=req.kind,
        label=req.label,
        endpoint=req.endpoint,
        secret=req.secret,
        default_model=req.default_model,
    )
    out: dict[str, Any] = {"ok": True, "provider": redacted}
    if req.validate:
        ok, err = ai_config.validate_provider(req.id)
        out["validated"] = ok
        out["validation_error"] = err
        # Re-read to pick up validated_at timestamp
        out["provider"] = ai_config.list_providers().get(req.id)
        # Fold the now-loaded key into os.environ for legacy callers
        ai_config.load_into_environment()
    return out


@app.delete("/api/ai/providers/{provider_id}")
async def delete_ai_provider(provider_id: str) -> dict[str, Any]:
    ok = ai_config.delete_provider(provider_id)
    return {"ok": ok}


@app.post("/api/ai/providers/{provider_id}/validate")
async def validate_ai_provider(provider_id: str) -> dict[str, Any]:
    ok, err = ai_config.validate_provider(provider_id)
    return {
        "ok": ok,
        "error": err,
        "provider": ai_config.list_providers().get(provider_id),
    }


@app.post("/api/ai/mcp")
async def upsert_ai_mcp(req: McpUpsertPayload) -> dict[str, Any]:
    spec = {
        "id": req.id,
        "label": req.label or req.id,
        "command": req.command,
        "args": req.args,
        "env": {k: v.model_dump() for k, v in req.env.items()},
        "enabled": req.enabled,
        "from_registry": req.from_registry,
    }
    return {"ok": True, "server": ai_config.upsert_mcp_server(spec)}


@app.delete("/api/ai/mcp/{server_id}")
async def delete_ai_mcp(server_id: str) -> dict[str, Any]:
    return {"ok": ai_config.delete_mcp_server(server_id)}


@app.put("/api/ai/routes")
async def set_ai_routes(req: RoutesPayload) -> dict[str, Any]:
    cleaned = ai_config.set_agent_routes(req.routes)
    return {"ok": True, "routes": cleaned}


@app.post("/api/settings/agents")
async def save_agent_models(req: AgentModelsPayload) -> dict[str, Any]:
    try:
        if req.all is not None:
            agents = agent_models.set_all(req.all)
        elif req.models:
            agents = agent_models.set_models(req.models)
        else:
            agents = agent_models.list_agents()
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "agents": agents}



# ─── Service keys (threat intel / OSINT APIs) ─────────────────────────
# Settings -> Service keys. Values are DPAPI-encrypted at rest and never
# returned; see threatdesk/service_keys.py.


class ServiceKeyPayload(BaseModel):
    value: str = ""


class CustomServiceKeyPayload(BaseModel):
    id: str
    label: str = ""
    env: str
    use: str = ""
    signup: str = ""
    value: str = ""


class ServiceKeyImportPayload(BaseModel):
    path: str


@app.get("/api/settings/service-keys")
async def list_service_keys() -> dict[str, Any]:
    return {"keys": service_keys.list_keys()}


@app.put("/api/settings/service-keys/{sid}")
async def set_service_key(sid: str, req: ServiceKeyPayload) -> dict[str, Any]:
    try:
        return {"ok": True, "key": service_keys.set_key(sid, req.value)}
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown service {sid!r}")


@app.post("/api/settings/service-keys/custom")
async def add_custom_service_key(req: CustomServiceKeyPayload) -> dict[str, Any]:
    try:
        entry = service_keys.add_custom(req.id, req.label, req.env, req.use, req.signup)
        if req.value:
            entry = service_keys.set_key(entry["id"], req.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "key": entry}


@app.delete("/api/settings/service-keys/custom/{sid}")
async def delete_custom_service_key(sid: str) -> dict[str, Any]:
    service_keys.delete_custom(sid)
    return {"ok": True}


@app.post("/api/settings/service-keys/import")
async def import_service_keys(req: ServiceKeyImportPayload) -> dict[str, Any]:
    """Import from a HoneyHive data/secrets.json or a `Name: key` notes
    file on this machine. Only fills empty slots; returns service ids,
    never values."""
    p = Path(req.path.strip().strip('"'))
    if p.suffix.lower() not in (".json", ".md", ".txt", ".env") or not p.is_file():
        raise HTTPException(status_code=400, detail="path must be an existing .json, .md, .txt or .env file")
    if p.stat().st_size > 256_000:
        raise HTTPException(status_code=400, detail="file too large for a key file")
    return {"ok": True, "imported": service_keys.import_file(p)}



# ─── Standalone Triage ────────────────────────────────────────────────
#
# A responder pastes a URL, a
# threat name, a suspicious file, or free text, the threat-triage agent
# produces a report + structured result. No packet mutations. The user

@app.post("/api/triage")
async def create_triage_endpoint(
    input_type: str = Form(...),            # "url" | "threat_name" | "text" | "file"
    input_ref: str = Form(""),              # URL or threat name (ignored for text/file)
    input_text: str = Form(""),             # pasted text content (ignored for url/threat_name/file)
    question: str = Form(""),               # responder's free-form question
    siem_preference: str = Form("generic"), # splunk | xsiam | elastic | sentinel | chronicle | kql | generic
    use_environment: str = Form("false"),   # "true" | "false" (form serialises booleans as strings)
    custom_name: str = Form(""),            # optional display name (e.g. RSS article headline)
    files: list[UploadFile] = File(default=[]),
) -> dict[str, Any]:
    """Kick off a standalone triage run. Returns the triage_id so the
    caller can subscribe to the SSE stream for live progress."""
    valid_inputs = {"url", "threat_name", "text", "file"}
    if input_type not in valid_inputs:
        raise HTTPException(status_code=400, detail=f"input_type must be one of {sorted(valid_inputs)}")

    if input_type == "url" and not input_ref.strip():
        raise HTTPException(status_code=400, detail="input_ref (URL) is required when input_type=url")
    if input_type == "threat_name" and not input_ref.strip():
        raise HTTPException(status_code=400, detail="input_ref (threat name) is required when input_type=threat_name")
    if input_type == "text" and not input_text.strip():
        raise HTTPException(status_code=400, detail="input_text is required when input_type=text")
    if input_type == "file" and not files:
        raise HTTPException(status_code=400, detail="at least one file is required when input_type=file")

    # Reserve the triage ID and dir up front so we can stream uploaded
    # files into it before the orchestrator task even starts.
    triage_id = triage_orchestrator.new_triage_id()
    triage_dir = triage_orchestrator.TRIAGES_DIR / triage_id
    attachments_dir = triage_dir / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)

    saved: list[str] = []
    hashes: dict[str, str] = {}
    # Stream chunks to disk (no whole-file buffering), then SHA-256 each
    # attachment on intake so the triage record carries its hash.
    for uf in files:
        name = triage_orchestrator.safe_attachment_name(uf.filename or "")
        dest = attachments_dir / name
        with dest.open("wb") as out:
            while chunk := await uf.read(65536):
                out.write(chunk)
        saved.append(name)
        hashes[name] = await asyncio.to_thread(_sha256_streaming, dest)

    # If the user uploaded files but didn't name an input_ref, use the
    # first filename as the ref so downstream rendering has a handle.
    if input_type == "file" and not input_ref.strip() and saved:
        input_ref = saved[0]

    # Hand off to the orchestrator, it will reuse our reserved ID.
    now_iso = _now_iso()
    input_payload = {
        "triage_id": triage_id,
        "input_type": input_type,
        "input_ref": input_ref.strip() or None,
        "input_text": input_text or None,
        "custom_name": (custom_name.strip() or None),
        "attached_files": saved,
        "attachment_sha256": hashes,
        "question": question.strip(),
        "siem_preference": siem_preference,
        "use_environment": use_environment.lower() == "true",
        "created_at": now_iso,
    }
    (triage_dir / "input.json").write_text(
        json.dumps(input_payload, indent=2), encoding="utf-8",
    )
    (triage_dir / "status.json").write_text(
        json.dumps({
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "error": None,
        }, indent=2),
        encoding="utf-8",
    )
    (triage_dir / "events.jsonl").touch()

    # Fire the agent run in the background.
    asyncio.create_task(triage_orchestrator._run_triage(triage_id))
    return {"ok": True, "triage_id": triage_id}


@app.get("/api/triages")
async def list_triages_endpoint() -> dict[str, Any]:
    return {"triages": triage_orchestrator.list_triages()}


@app.get("/api/triage/{triage_id}")
async def get_triage_endpoint(triage_id: str) -> dict[str, Any]:
    try:
        return triage_orchestrator.read_triage(triage_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"triage {triage_id!r} not found")


@app.delete("/api/triage/{triage_id}")
async def delete_triage_endpoint(triage_id: str) -> dict[str, Any]:
    ok = triage_orchestrator.delete_triage(triage_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"triage {triage_id!r} not found")
    return {"ok": True, "deleted": triage_id}


class TriageRenameRequest(BaseModel):
    custom_name: str | None = Field(default=None, max_length=200)


@app.patch("/api/triage/{triage_id}")
async def rename_triage_endpoint(triage_id: str, req: TriageRenameRequest) -> dict[str, Any]:
    """Set or clear the responder-facing display name for a triage.

    Pass ``custom_name: null`` or an empty string to revert back to the
    agent's headline / input_ref as the label. Used by the UI to let
    the responder rename auto-created triages (e.g. one kicked off
    from an RSS feed whose label would otherwise be a long URL).
    """
    ok = triage_orchestrator.rename_triage(triage_id, req.custom_name)
    if not ok:
        raise HTTPException(status_code=404, detail=f"triage {triage_id!r} not found")
    return {"ok": True, "triage_id": triage_id, "custom_name": (req.custom_name or "").strip() or None}


@app.get("/api/triage/{triage_id}/stream")
async def stream_triage_endpoint(triage_id: str) -> StreamingResponse:
    """SSE: replay events.jsonl then push live events as the agent runs."""
    triage_dir = triage_orchestrator.TRIAGES_DIR / triage_id
    if not triage_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"triage {triage_id!r} not found")

    async def gen():
        # Replay historic events first so late joiners catch up.
        for ev in triage_orchestrator._read_events(triage_dir / "events.jsonl"):
            body = json.dumps(ev, default=str)
            yield f"event: agent_event\ndata: {body}\n\n".encode("utf-8")

        # Initial snapshot so the UI can render the current report/result
        # without a separate fetch.
        try:
            snap = triage_orchestrator.read_triage(triage_id)
            body = json.dumps(snap, default=str)
            yield f"event: snapshot\ndata: {body}\n\n".encode("utf-8")
        except FileNotFoundError:
            pass

        listener = triage_orchestrator.subscribe(triage_id)
        ping_due_at = 0
        try:
            while True:
                now_ms = int(asyncio.get_event_loop().time() * 1000)
                if now_ms >= ping_due_at:
                    yield b"event: ping\ndata: {}\n\n"
                    ping_due_at = now_ms + 15_000
                try:
                    ev = await asyncio.wait_for(listener.get(), timeout=0.75)
                except asyncio.TimeoutError:
                    continue
                body = json.dumps(ev, default=str)
                yield f"event: agent_event\ndata: {body}\n\n".encode("utf-8")

                # When the run finishes, push one last snapshot so the UI
                # picks up report.md + result.json without re-fetching,
                # then close the stream.
                if ev.get("kind") == "triage_status" and ev.get("status") in ("done", "error"):
                    try:
                        snap = triage_orchestrator.read_triage(triage_id)
                        body = json.dumps(snap, default=str)
                        yield f"event: snapshot\ndata: {body}\n\n".encode("utf-8")
                    except FileNotFoundError:
                        pass
                    yield b"event: done\ndata: {}\n\n"
                    break
        finally:
            triage_orchestrator.unsubscribe(triage_id, listener)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )



# ─── TIP (Threat Intelligence Platform), lightweight local catalog ──
#
# Walks triages, de-duplicates IOCs, and attaches external enrichment on
# demand (VT / URLhaus / ThreatFox / AbuseIPDB). Derived from triage
# results on disk; there is no separate TIP store. MISP Event JSON export
# (one Event per triage) pushes into a real MISP when wanted.

TIP_CACHE_DIR = Path(os.environ.get("TIP_CACHE_DIR", REPO_ROOT / "tip" / "enrichment"))
TRIAGES_DIR_PATH = triage_orchestrator.TRIAGES_DIR


@app.get("/api/tip/iocs")
async def tip_list_iocs(
    q: str | None = None,
    ioc_type: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Return the aggregated IOC catalog across every triage on disk. Filterable by substring (q) and canonical type."""
    def _build() -> list[dict[str, Any]]:
        return tip_catalog.build_catalog(TRIAGES_DIR_PATH)
    catalog = await asyncio.to_thread(_build)
    out = catalog
    if ioc_type:
        t = tip_catalog._canonical_type(ioc_type)
        out = [r for r in out if r["type"] == t]
    if q:
        needle = q.lower().strip()
        out = [r for r in out if needle in (r["normalized_value"] or "").lower() or needle in (r["value"] or "").lower()]
    limit = max(1, min(5000, int(limit)))
    return {
        "iocs": out[:limit],
        "total": len(out),
        "summary": tip_catalog.summarize(catalog),
    }


@app.get("/api/tip/ioc/{ioc_type}/{value:path}")
async def tip_get_ioc(ioc_type: str, value: str) -> dict[str, Any]:
    """Detail view for a single IOC. Returns the catalog record +
    cached enrichment if available (never triggers a fresh lookup,
    use POST /enrich for that so the UI controls the cost)."""
    def _build() -> list[dict[str, Any]]:
        return tip_catalog.build_catalog(TRIAGES_DIR_PATH)
    catalog = await asyncio.to_thread(_build)
    rec = tip_catalog.find(catalog, ioc_type=ioc_type, value=value)
    if not rec:
        raise HTTPException(status_code=404, detail=f"IOC {ioc_type}:{value!r} not found in catalog")

    # Look up cached enrichment without triggering new fetches.
    cache_path = tip_enrichers._cache_path_for(
        TIP_CACHE_DIR,
        tip_catalog._canonical_type(ioc_type),
        tip_catalog._normalize_value(tip_catalog._canonical_type(ioc_type), value),
    )
    enrichment: dict[str, Any] | None = None
    if cache_path.exists():
        try:
            enrichment = json.loads(cache_path.read_text(encoding="utf-8"))
            enrichment["from_cache"] = True
        except (OSError, json.JSONDecodeError):
            enrichment = None
    return {"ioc": rec, "enrichment": enrichment}


@app.post("/api/tip/ioc/{ioc_type}/{value:path}/enrich")
async def tip_enrich_ioc(ioc_type: str, value: str, force: bool = False) -> dict[str, Any]:
    """Run supported enrichers for this IOC. Results are disk-cached
    (24h TTL). Pass ``?force=1`` to refresh even if a cached result
    exists."""
    t = tip_catalog._canonical_type(ioc_type)
    v = tip_catalog._normalize_value(t, value)
    result = await tip_enrichers.enrich(t, v, TIP_CACHE_DIR, force=force)
    return result


@app.get("/api/tip/enrichers")
async def tip_enrichers_status() -> dict[str, Any]:
    """Which enrichment adapters are configured + what they support."""
    return {"enrichers": tip_enrichers.enricher_status()}


@app.get("/api/tip/misp-export")
async def tip_misp_export(triage_id: str | None = None) -> dict[str, Any]:
    """MISP-compatible Event JSON. With ``triage_id``: that triage's Event,
    ready for PyMISP.add_event(). Without: {"response": [Event, ...]} for
    every completed triage."""
    if triage_id:
        try:
            return tip_misp.event_for_triage(triage_orchestrator.read_triage(triage_id))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"triage {triage_id!r} not found")
    details: list[dict[str, Any]] = []
    for row in triage_orchestrator.list_triages():
        try:
            d = triage_orchestrator.read_triage(row["triage_id"])
        except FileNotFoundError:
            continue
        if d.get("result"):
            details.append(d)
    return tip_misp.bulk_export(details)


# ─── Inventory sources (tech-stack doc, JSON, env list, ServiceNow slot) ──

@app.get("/api/inventory/sources")
async def inventory_sources() -> dict[str, Any]:
    return {"sources": inventory.sources_status(), "columns": inventory.CSV_COLUMNS,
            "asset_count": len(inventory.load_assets())}


@app.put("/api/inventory/csv")
async def inventory_upload_csv(file: UploadFile = File(...)) -> dict[str, Any]:
    """Replace the tech-stack CSV. The previous file is kept as .bak."""
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV larger than 20 MB")
    try:
        return inventory.save_csv(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/inventory/template.csv")
async def inventory_template() -> FileResponse:
    return FileResponse(REPO_ROOT / "config" / "tech-stack.template.csv", media_type="text/csv",
                        filename="tech-stack.template.csv")


@app.get("/api/threats/feed")
async def threats_feed_endpoint(force: bool = False) -> dict[str, Any]:
    """Return the latest aggregated threat feed. Pulls CISA CSA, KEV,
    The Hacker News, BleepingComputer, Krebs on Security, and SANS ISC
    on a 30-minute TTL. `?force=1` bypasses the cache (use sparingly)."""
    return await threat_feed.get_feed(force=force)


# ─── Vulnerabilities ─────────────────────────────────────────────────

_vuln_feed_task: "asyncio.Task | None" = None


def _warm_vuln_caches() -> None:
    """Load KEV, build the inventory index and fetch vulnerability news in
    the background at startup, so the first visit to the tab is fast."""
    import threading

    def run() -> None:
        try:
            from threatdesk import vulns as _vulns
            kev = _vulns.kev_catalog()
            _vulns._index(kev, _vulns.load_inventory())
            _vulns.vuln_news_items([])
        except Exception as e:  # noqa: BLE001
            logging.getLogger(__name__).info("vuln cache warm-up skipped: %s", e)
    threading.Thread(target=run, name="vuln-warmup", daemon=True).start()


if os.environ.get("THREATDESK_SKIP_WARMUP") != "1" and "pytest" not in sys.modules:
    _warm_vuln_caches()


async def _vuln_news_feed() -> dict[str, Any] | None:
    """News feed for CVE mention counts, without making the page wait on
    six RSS fetches. Waits up to 2 s; otherwise the refresh keeps going
    in the background and the next search picks it up."""
    global _vuln_feed_task
    if _vuln_feed_task is None or _vuln_feed_task.done():
        _vuln_feed_task = asyncio.create_task(threat_feed.get_feed())
    try:
        return await asyncio.wait_for(asyncio.shield(_vuln_feed_task), timeout=2)
    except Exception:  # noqa: BLE001 (timeout or fetch error: no news counts this time)
        return None


@app.get("/api/vulns")
async def vulns_search(q: str = "", scope: str = "all", limit: int = 60) -> dict[str, Any]:
    """Known exploited vulnerabilities: search by technology, CVE id or
    ATT&CK technique; scope all | org (matches the org inventory) | hot."""
    from threatdesk import vulns as _vulns
    if scope not in ("all", "org", "hot"):
        raise HTTPException(status_code=400, detail="scope must be all, org or hot")
    feed = await _vuln_news_feed()
    items = _vulns.vuln_news_items((feed or {}).get("items") or [], cached_only=True)
    news, _ = _vulns.news_mentions({"items": items})
    try:
        return await asyncio.to_thread(_vulns.search, q[:120], scope, news, max(1, min(limit, 200)))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"vulnerability catalog unavailable: {str(e)[:200]}")


_vuln_news_task: "asyncio.Task | None" = None


@app.get("/api/vulns/inventory")
async def vulns_inventory() -> dict[str, Any]:
    """The org technology inventory with known-exploited counts per product."""
    from threatdesk import vulns as _vulns
    try:
        return await asyncio.to_thread(_vulns.inventory_view)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"vulnerability catalog unavailable: {str(e)[:200]}")


@app.get("/api/vulns/news")
async def vulns_news(mine: bool = False, limit: int = 60) -> dict[str, Any]:
    """Vulnerability news: exploitation research and advisories plus
    Triage-feed stories that name a CVE, tagged against KEV and the org
    inventory. First load waits up to 8 s for the sources."""
    from threatdesk import vulns as _vulns
    global _vuln_news_task
    feed = await _vuln_news_feed()
    feed_items = (feed or {}).get("items") or []
    if _vuln_news_task is None or _vuln_news_task.done():
        _vuln_news_task = asyncio.create_task(asyncio.to_thread(_vulns.vuln_news_items, feed_items))
    try:
        raw = await asyncio.wait_for(asyncio.shield(_vuln_news_task), timeout=8)
    except Exception:  # noqa: BLE001
        raw = await asyncio.to_thread(_vulns.vuln_news_items, feed_items, True)
    return await asyncio.to_thread(_vulns.vuln_news, None, mine, max(1, min(limit, 200)), None, raw)


@app.get("/api/vulns/{cve}")
async def vulns_detail(cve: str) -> dict[str, Any]:
    from threatdesk import vulns as _vulns
    feed = await _vuln_news_feed()
    _, items = _vulns.news_mentions({"items": _vulns.vuln_news_items((feed or {}).get("items") or [], cached_only=True)})
    d = await asyncio.to_thread(_vulns.detail, cve, items)
    if not d:
        raise HTTPException(status_code=404, detail=f"{cve} not found in KEV or NVD")
    return d


class VulnTrackingIn(BaseModel):
    status: str
    owner: str = ""
    ticket: str = ""
    note: str = ""


@app.put("/api/vulns/{cve}/tracking")
async def vulns_set_tracking(cve: str, body: VulnTrackingIn) -> dict[str, Any]:
    """Local remediation tracking. Jira / ServiceNow / Glean sync writes
    the same record later (provider + external_ref)."""
    from threatdesk import vulns as _vulns
    try:
        return await asyncio.to_thread(_vulns.set_tracking, cve, body.status, body.owner, body.ticket, body.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))



# ─── Static frontend ──────────────────────────────────────────────────

def _index() -> FileResponse:
    idx = WEB_DIST_DIR / "index.html"
    if idx.exists():
        return FileResponse(idx, media_type="text/html")
    raise HTTPException(status_code=500, detail="UI not built: run `cd web && npm install && npm run build`.")


@app.get("/")
async def root() -> FileResponse:
    return _index()


if (WEB_DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST_DIR / "assets"), name="assets")


@app.get("/{path:path}")
async def spa_fallback(path: str) -> FileResponse:
    """Top-level static files from web-dist, else the SPA shell. Registered
    after every /api route so API paths match first."""
    if path.startswith("api/") or path.startswith("assets/"):
        raise HTTPException(status_code=404, detail=f"not found: /{path}")
    f = (WEB_DIST_DIR / path).resolve()
    if f.is_file() and f.is_relative_to(WEB_DIST_DIR.resolve()):
        return FileResponse(f)
    return _index()
