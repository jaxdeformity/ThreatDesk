# ThreatDesk: Threat Triage + Vulnerabilities carve-out from SOC-in-a-Box

Date: 2026-11-18
Status: draft, awaiting Jax's approval
Working name: **ThreatDesk** (Claude's call; rename at will)

## Intent

Take SOC-in-a-Box's Threat Triage and Vulnerabilities capabilities and make them a separate product that Jax can bring into a large enterprise. There it does two jobs: it is a vulnerability dashboard ("which exploited vulns hit *our* stack, and where is remediation"), and it runs threat-ops triage through an agent ("what is this threat, does it matter to us, what do we do"). SOC-in-a-Box stays as is: it is the full CSIRT/demo product, and this is a narrower product aimed at a different buyer.

## Goals

- A standalone repo at `H:\AI Code Projects\ThreatDesk\` that installs and runs on a single machine without SOC-in-a-Box present.
- **Triage**: same capability as today. URL, pasted text, an uploaded file, or a threat name goes in. The `threat-triage` agent produces a report plus structured result (key findings, IOCs, hunt queries, recommended actions), streamed live to the UI. The threat feed rail stays as a source of triage input.
- **Vulns**: same capability as today. KEV, EPSS and NVD are matched against the org inventory; the hot-now view, search by tech/CVE/technique, CVE detail, vulnerability news, and local remediation tracking all carry over.
- **Threat feed**: the aggregated public feed (CISA, KEV, THN, BleepingComputer, Krebs, SANS ISC, CSHub) powers both the triage rail and the vulns news.
- **Intel (TIP)**: the IOC catalog, enrichers and MISP export, fed **only from triages**.
- **Tech-stack doc**: an enterprise can describe its environment by filling in a template (CSV, plus the existing inventory JSON format) rather than editing `.env`.
- **ServiceNow-ready**: an inventory-source interface that a ServiceNow CMDB adapter plugs into later without touching the vulns logic. Tracking records keep the existing `provider` / `external_ref` fields.

## Non-goals (v1)

- SSO, multi-user, roles, a hosted/shared server deployment.
- A ServiceNow adapter of any kind (read or write). Only the seam is built.
- Promoting a triage to an incident. Incidents, the CSIRT agents (IC, Scribe, Investigative Lead, Investigator), swarm, Velociraptor, deception, EvidenceForge, war room, Mission Control and the case report do not come across.
- A shared core package with SOC-in-a-Box. Drift between the two repos is accepted (approach A).

## Anti-goals

- Shipping incident-response machinery the enterprise didn't ask for. If someone opening the repo finds `incidents/`, Velociraptor, or the CSIRT agents, the carve-out failed.
- Org data leaving the machine for public intel lookups. The current vulns rule stays: only CVE ids and search words go out, and stack matching happens locally.
- Any dependency on Jax's personal setup (Max subscription billing, the `H:` vault, Jax's keys).

## Constraints

- Python 3.11+, FastAPI + uvicorn (same as SOCbox). React + Vite + TanStack Query + Tailwind frontend (same as `web-react`).
- The triage agent runs through the Claude Code CLI / Agent SDK, as today (`claude_runner` + `model_policy` fallback). So Claude Code has to be installed on the target machine. This goes in the install doc.
- **Billing:** SOCbox blanks `ANTHROPIC_API_KEY` so agents bill to Jax's Max plan. In ThreatDesk, the default flips: use the enterprise API key (or Bedrock/Vertex env) if one is set. A runtime setting keeps the subscription mode for Jax's own testing. (Claude's call.)
- Chain-of-custody habits from SOCbox carry over for triage artifacts: each uploaded attachment is SHA-256 hashed on intake, `events.jsonl` is append-only, and timestamps are ISO 8601 UTC.
- All sample/fixture data is synthetic (TEST-NET IPs, `example.com`).
- Runtime data (`triages/`, `config/cache/`, `config/vuln_tracking.json`, `config/environment.json`, filled tech-stack files, `.env`) is gitignored.

## Approaches considered

- **A. Copy and trim into a new repo — chosen.** Copy the needed modules, build a slim API and a slim UI. It is truly standalone and free to reshape for enterprises. The cost is that fixes don't flow between repos automatically.
- B. Shared core package imported by both products. No drift, but SOCbox has to be refactored now, and every later change has to keep both products working. Rejected: it slows exactly the enterprise customization this is for.
- C. A trimmed edition of SOCbox in the same repo. Cheapest, but the IR machinery still ships. Rejected: not standalone.

## What gets built

### Backend (`threatdesk/` package + `api/`)

Copied from `soc_in_a_box/` and trimmed:

| Module | Change |
|---|---|
| `vulns.py` | Inventory loading moves behind `inventory.py`. `SOC_ORG_*` env names become `THREATDESK_*`, with the old names still accepted. User agent string renamed. |
| `threat_feed.py` | As is. |
| `triage_orchestrator.py` | Remove the Primus run path and every "promote" mention. Claude only. |
| `claude_runner.py`, `model_policy.py`, `runtime_settings.py`, `debug_logger.py`, `envfile.py` | As is, apart from the billing default above. |
| `llm_providers.py`, `ai_config.py`, `service_keys.py` | Trim to the providers/keys triage and vulns use (Anthropic, NVD, VirusTotal, the enricher keys). No Primus. |
| `tip_catalog.py` | Walk `triages/` only. Drop the incident walk. |
| `tip_enrichers.py`, `tip_misp.py` | As is. |

New:

- **`inventory.py`**: an `InventorySource` protocol (`name`, `load() -> list[Asset]`, `status()`), with the asset shape that `vulns.load_inventory` already uses (id, category, vendor, product, version, environment, count, owner, criticality, internet_facing, match[]). Sources:
  - `StackDocSource`: reads `config/tech-stack.csv` (template shipped as `config/tech-stack.template.csv` with header + 3 synthetic rows) and/or the existing inventory JSON.
  - `EnvListSource`: the legacy comma list.
  - The ServiceNow slot exists only as a documented interface plus a `NotConfigured` status in the UI. No adapter code.
  - Sources merge with de-duplication by vendor+product+version.
- **`api/main.py`**: one FastAPI app with just these routes (ported from SOCbox `api/main.py`):
  - `/api/triage*` (create with upload, list, get, delete, rename, SSE stream)
  - `/api/threats/feed`
  - `/api/vulns*` (search, inventory, news, detail, tracking PUT)
  - `/api/tip/*` (iocs, ioc detail, enrich, enrichers, misp-export)
  - `/api/environment` GET/POST
  - `/api/settings/runtime`, `/api/ai/*`, `/api/settings/service-keys*`
  - `/api/inventory/sources` (new: lists sources and their status, and lets you re-upload the CSV)
  - The startup vuln-cache warm-up stays.
- **Agent definition**: `.claude/agents/threat-triage.md`, copied, with the "Legacy path, in-incident triage" section removed. The environment cross-reference step also reads the inventory, so triage and vulns share one view of the stack.
- **Entry point**: `threatdesk` console script that serves the API plus the built UI on localhost (mirrors `soc-serve`, without the tray/supervisor).

### Frontend (`web/`)

A new slim Vite app. Copied from `web-react/`: `features/triage/*`, `features/vulns/*`, `features/threat-intel/*`, `hooks/useTriageStream.ts`, the `api/client` + types they use, `kit/ContextStrip`, the `components/ui` pieces they import (dialog, toast), `lib/cn`, and the styles/tokens. New: a minimal shell with a top bar and four tabs (**Triage · Vulns · Intel · Settings**), defaulting to Vulns. Settings covers AI provider/keys, the environment profile (SIEM preference, crown jewels: the fields the triage agent reads from `environment.json`), and inventory sources with CSV upload. The MK1/MK2 shells, onboarding gate, and everything incident-related stay behind.

### Tests

- Port `tests/test_vulns.py` and `VulnsView.test.tsx`.
- New tests: `inventory.py` (CSV parse, merge/de-dup, legacy env list, malformed rows rejected with a clear error), `tip_catalog` triage-only walk, triage orchestrator lifecycle with a fake runner (status transitions, events append-only, attachment hashing), and an API smoke test per route group.
- Network calls (KEV/EPSS/NVD/feeds) are mocked with recorded synthetic fixtures.

### Docs

`README.md` (what it is, install, first run), `docs/TECH-STACK.md` (how to fill the template and what each column does to matching), `docs/SERVICENOW.md` (the interface a future adapter implements and the CMDB tables it would read), `.env.example`.

## Decisions after builder review (2026-11-18)

Framing from Jax: this is a **standalone demo** to show an enterprise what's possible. Jax will rearchitect afterwards. So pick the simplest path that runs cleanly and leaves out SOCbox machinery. Don't harden for production.

**Jax decided:**
- **Primus is removed completely**: the run path, the provider, the UI picker, `/api/llm/status`, `.claude/scripts/primus-classify.py`, and the agent-prompt references. Triage runs on Claude only.

**Claude's calls** (marked so Jax can check them):
1. **Platform:** Windows, run from a git checkout. Keep the DPAPI secret store and the repo-root-relative data paths (`Path(__file__)` pattern). No wheel/installer, and no separate data directory.
2. **Model credentials:** an Anthropic API key entered in Settings → AI (DPAPI store), or set in the real OS environment. The `envfile` allowlist stays as is for `ANTHROPIC_*` (don't put it in `.env`). The subscription mode (blank key) remains available as a runtime setting for Jax's own demo machine.
3. **Models:** triage defaults to `claude-opus-5-5`, and the agent frontmatter matches. The cyber-refusal fallback is kept but configurable, and it is **off by default** (the 4.7 exemption is tied to Jax's account). Bedrock/Vertex model-ID mapping is out of scope.
4. **Permissions:** keep `--dangerously-skip-permissions` for the demo, and note it in the README as a pre-production item to replace with an explicit allowed-tools list.
5. **Port and agent access:** default port **8444** (SOCbox owns 8443), configurable via `THREATDESK_PORT`. The agent prompt reads the port from that env var. The agent gets environment and inventory from `GET /api/environment`, whose response now includes the merged inventory.
6. **One asset list:** the inventory (CSV + JSON + legacy env list) is the only asset source. Drop `environment.assets` from the example and the UI. `environment.json` keeps the org profile, SIEM preference, crown jewels and intel feeds.
7. **Org data and the model:** the stack goes into the model context only when the analyst ticks "use environment" on that triage. Add a prompt rule that the agent's web searches and fetches use threat terms only, never org product names, hostnames or asset IDs.
8. **MISP export:** one MISP Event per triage (`/api/tip/misp-export?triage_id=`). Rewrite `tip_misp` around the triage `result.json` (iocs[] + key findings).
9. **Inventory CSV columns:** `id, category, subcategory, vendor, product, version, patched_through, environment, count, owner, criticality, internet_facing, match`. `match` is a semicolon-separated alias list. Precedence on a de-dup collision: CSV > JSON > env list. Env-list terms match on product only. Re-uploading the CSV replaces the file (the previous one is kept as `.bak`).
10. **Modules that aren't "as is" after all:**
    - `envfile` gets `THREATDESK_*` names alongside `SOC_ORG_*`.
    - `threat_feed` gets a neutral User-Agent (no personal URL).
    - `tip_catalog.build_catalog` loses the incidents parameter and `related_incidents`.
    - The `store._now_iso` dependency is inlined.
    - The triage system prompt and report text are rebranded ThreatDesk, and every "promote to incident" mention is removed.
    - `agent_models` is copied, trimmed to the one triage agent.
    - `mcp-defaults.json` is copied.
    - The AI routing list (`CANONICAL_AGENTS_FOR_ROUTING`) is trimmed to `threat-triage`.
    - `threat-triage.md` loses the in-incident legacy section and the `memory: project` line.
11. **Frontend:**
    - Use react-router (Vulns → `/triage?threat=` deep links and query params need it).
    - Remove the promote UI from `TriageView`.
    - Reword the incident-origin copy and styling in `ThreatIntelView`.
    - Reuse `features/settings/AISettingsPanel.tsx` and `ServiceKeysCard.tsx`, not new Settings components.
12. **Tooling:** `curl` and `jq` are listed as prerequisites in the README (both ship with Git for Windows / winget). No rewrite of the agent's shell steps.
13. **Gitignore** also covers `logs/`, `tip/enrichment/`, `config/ai_config.json`, `config/service_keys.json` and `config/runtime-settings.json`.

## Left to the builder

- Exact file layout inside `web/` and how much of the SOCbox design-token layer is needed.
- Whether `ai_config`/`service_keys` trim cleanly or are easier rewritten small.
- Port order and commit granularity.
- The git repo is initialized locally. No remote is created or pushed without Jax asking.
