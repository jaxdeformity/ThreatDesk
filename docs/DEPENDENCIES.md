# SOC-in-a-Box couplings and what replaced them

Every dependency on SOC-in-a-Box found during the carve-out (2026-11-18), and how ThreatDesk stands without it. `tests/test_isolation.py` fails the build if `soc_in_a_box`, `SOC-in-a-Box`, `8443`, `primus` or `polaris` reappears in product code.

| Coupling in SOC-in-a-Box | Where | ThreatDesk replacement |
|---|---|---|
| Python package `soc_in_a_box` | every module | Copied into `threatdesk/` and trimmed (copy-and-trim, no shared package). |
| `api/store._now_iso` in the triage create route | `api/main.py` | Inlined `_now_iso()` in `api/main.py`. |
| Port 8443, hard-coded in the agent prompt (`curl …:8443/api/environment`) and the Vite proxy | `threat-triage.md`, `vite.config.ts` | `THREATDESK_PORT` (default 8444) is used everywhere; the agent curls `${THREATDESK_PORT:-8444}`. |
| Inventory from `SOC_ORG_INVENTORY` / `SOC_ORG_TECH_STACK` only, plus `environment.json.assets` | `vulns.py`, environment JSON | `threatdesk/inventory.py`: tech-stack CSV > inventory JSON > env list, with a ServiceNow slot. `environment.assets` was removed, and `GET /api/environment` returns the merged `inventory`. `SOC_ORG_*` names are still accepted. |
| Synthetic demo inventory under `scenarios/org-inventory/` | SOCbox scenarios | Copied to `samples/meridian-global.{json,csv}` + `build_inventory.py`. |
| Primus (local Ollama classifier): triage run path, `/api/llm/*`, UI picker, `.claude/scripts/primus-classify.py`, agent step 0 | orchestrator, API, TriageView, agent | Removed. Triage is Claude-only. |
| Promote triage → incident (`/api/triage/{id}/promote-to-incident`, "Create incident" button) | API, TriageView | Removed. The button became **MISP export** for that triage. |
| In-incident legacy path in the agent (`incidents/<id>/`, `packet.py`) | `threat-triage.md` | Removed. |
| TIP catalog walks `incidents/` + `triages/`; `related_incidents` | `tip_catalog.py` | `build_catalog(triages_dir)`, triage-only; `related_incidents` dropped. |
| MISP export built on incident packets (`event_for_incident`) | `tip_misp.py`, `/api/tip/misp-export` | Rewritten as `event_for_triage(detail)`, one Event per triage; `?triage_id=` param; bulk = all completed triages. |
| Agents billed to the operator's Max subscription (API key blanked unless `SOC_AGENT_BILLING=api`) | `claude_runner.agent_env` | Inverted: the API key / Bedrock / Vertex env is inherited by default; `use_subscription` runtime setting blanks it. |
| Cyber-refusal fallback to `claude-opus-4-7` always on (tied to Jax's exemption) | `model_policy`, `runtime_settings` | Kept but opt-in (`cyber_fallback_enabled: false`). Triage default model is `claude-opus-5-5`. |
| Runtime settings for the whole CSIRT (coordinator, scribe, swarm, autonomous, validator…) | `runtime_settings.py` | Rewritten with only `triage_model`, `cyber_fallback_*`, `use_subscription` and `runner_backend`. |
| AI routing roster = full CSIRT (`CANONICAL_AGENTS_FOR_ROUTING`) | `api/main.py` | Trimmed to `default` + `threat-triage`. |
| User-Agent with a personal GitHub URL | `threat_feed.py`, `vulns.py` | `ThreatDesk/0.1`. |
| `SOC_LOG_DIR`, `SOC_DEBUG`, `SOC_SKIP_WARMUP` | `debug_logger`, API | `THREATDESK_LOG_DIR`, `THREATDESK_DEBUG`, `THREATDESK_SKIP_WARMUP`. |
| Attachments saved without a hash | triage create route | SHA-256 recorded in `input.json.attachment_sha256` on intake; filenames reduced to a basename. |
| Frontend: POLARIS MK1/MK2 shells, onboarding gate, command line, incident API client (~700 lines) | `web-react/src` | New four-tab shell (`web/src/shell/Shell.tsx`); `api/client.ts` trimmed to triage/vulns/TIP/settings/inventory calls. |
| Settings view: LLM providers (Primus), EvidenceForge, specialist models, system checks, reset incidents, dispatch roster | `SettingsView.tsx` | Rewritten: Technology inventory (CSV upload), Environment profile, Triage agent, Service keys, AI providers. |
| Static serving of `web-react-dist/`, legacy `web/`, CyberChef | `api/main.py` | Serves `web-dist/` only. |

## External dependencies that remain (not SOC-in-a-Box)

| Dependency | Why | Alternative if it's blocked in the enterprise |
|---|---|---|
| Claude Code CLI | Runs the triage agent (tools: WebFetch, WebSearch, Read/Write, Bash) | Point it at Bedrock/Vertex via env vars, or replace `claude_runner` with a direct Messages API tool-use loop (more code; loses Claude Code's built-in web tools). |
| `--dangerously-skip-permissions` | Unattended agent runs | Explicit `--allowedTools` list (see README, "Before production"). |
| Windows DPAPI (`ai_config`, `service_keys`) | Secret storage at rest | OS keyring (`keyring` package) or an enterprise vault, if moved off Windows. |
| `curl`, `jq` | Agent shell steps | `curl` ships with Windows; `winget install jqlang.jq`, or have the agent use WebFetch / Python for the environment read. |
| Public feeds: CISA KEV, FIRST EPSS, NIST NVD, vendor/news RSS | Vulns + threat feed | Behind a proxy: set `HTTPS_PROXY`. Air-gapped: mirror KEV/EPSS/NVD JSON internally and change the URLs in `vulns.py` / `threat_feed.py`. |
| Google Fonts (IBM Plex Mono, Inter) | UI typography | Self-host the fonts in `web/public/` if outbound font fetches are blocked; the UI falls back to system fonts otherwise. |
