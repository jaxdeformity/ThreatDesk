# ThreatDesk carve-out: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (native; Jax said "go") to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone ThreatDesk repo, `H:\AI Code Projects\ThreatDesk`, pushed as a private GitHub repo. It reproduces SOC-in-a-Box's Triage, Vulns, Threat feed and Intel (TIP) behavior with no import, path or port dependency on SOC-in-a-Box.

**Architecture:** Copy and trim (approach A). Python package `threatdesk/` holds the ported modules. `api/main.py` is a slim FastAPI app carrying only the routes in the spec. `web/` is a slim Vite/React app that builds into `web-dist/`, which FastAPI serves. Data stays repo-root-relative, as in SOCbox.

**Tech Stack:** Python 3.11+, FastAPI, uvicorn, claude-agent-sdk/Claude Code CLI; React 18, Vite, TanStack Query, react-router 7, Tailwind 3, vitest.

**Spec:** `docs/superpowers/specs/2026-11-18-threatdesk-carveout-design.md` (including "Decisions after builder review").

## Global Constraints

- Nothing in the repo imports `soc_in_a_box`, references `SOC-in-a-Box` paths, or uses port 8443. The test `tests/test_isolation.py` enforces this.
- No Primus anywhere: `grep -ri primus` returns nothing outside `docs/`.
- No incident concepts in product code: no `promote`, `incidents/`, or `INC-` handling. `related_incidents` is removed.
- Default port is `8444`, read from `THREATDESK_PORT`.
- Env names: `THREATDESK_TECH_STACK` and `THREATDESK_INVENTORY`, with `SOC_ORG_TECH_STACK` and `SOC_ORG_INVENTORY` still accepted as fallbacks.
- Triage model defaults to `claude-opus-5-5`. The cyber fallback is off by default (`cyber_fallback_enabled: false`).
- No personal URLs or names in User-Agent strings. The UA is `ThreatDesk/0.1`.
- All fixtures are synthetic.

## Review Focus

1. **Fresh clone, no `config/environment.json`, no inventory.** Vulns renders with an empty-inventory hint, and triage with "use environment" still runs. Pinned by `test_api_smoke.py::test_vulns_empty_inventory` and `test_environment_fallback_example`.
2. **Malformed tech-stack CSV** (missing `product`, bad boolean, BOM header). Bad rows are skipped and reported, and the good rows still load. Pinned in Task 2.
3. **Triage attachment upload.** It is SHA-256 hashed and recorded in `input.json`, and the filename can't escape the triage dir (path traversal). Pinned in Task 4.
4. **Threat feed upstream down.** `/api/threats/feed` returns the cached or empty feed, not a 500. Pinned in Task 5 with a monkeypatched fetch that raises.
5. **Vulns → Triage deep link.** `/triage?threat=CVE-...` prefills the triage input. Pinned by `web` test `TriageView.deeplink.test.tsx`.

---

### Task 1: Repo scaffold + backend support modules

**Files:**
- Create: `pyproject.toml` (name `threatdesk`, deps fastapi, uvicorn[standard], pydantic, python-multipart, claude-agent-sdk; script `threatdesk = "threatdesk.serve:main"`), `.gitignore`, `.env.example`, `README.md` (stub), `threatdesk/__init__.py`
- Copy and trim from `SOC-in-a-Box/soc_in_a_box/`: `debug_logger.py`, `envfile.py`, `model_policy.py`, `runtime_settings.py`, `claude_runner.py`, `ai_config.py`, `service_keys.py`, `agent_models.py`
- Copy: `config/mcp-defaults.json`, `config/environment.example.json` (drop `assets`)
- Test: `tests/test_isolation.py`, port `tests/test_service_keys.py`

**Interfaces:**
- Produces:
  - `threatdesk.claude_runner.ClaudeRunner` and `agent_env()`. The billing default changes: the env API key is kept unless the runtime setting `use_subscription` is true.
  - `threatdesk.model_policy.run_turn_with_fallback(...)`, unchanged signature.
  - `threatdesk.runtime_settings.load() -> dict`, with keys `triage_model` (default `claude-opus-5-5`), `cyber_fallback_enabled` (False), `cyber_fallback_model`, and `use_subscription` (False).
  - `REPO_ROOT` in each module resolves to the ThreatDesk root.

- [ ] Step 1: write `tests/test_isolation.py`:
  - `test_no_socbox_imports` walks `threatdesk/`, `api/`, `.claude/` and `web/src`, and asserts none contain `soc_in_a_box`, `SOC-in-a-Box`, `8443` or `primus` (case-insensitive).
  - `test_runtime_defaults` asserts `triage_model == "claude-opus-5-5"` and `cyber_fallback_enabled is False`.
- [ ] Step 2: run `pytest tests -q`. Expected: FAIL (modules missing).
- [ ] Step 3: copy the modules and rewrite imports `soc_in_a_box` → `threatdesk`.
  - Trim: drop non-triage agents in `agent_models`, drop Primus/local providers in `ai_config`, and drop Primus keys in `service_keys`.
  - Add `THREATDESK_*` to the `envfile` allowlist.
  - Add the new runtime-setting keys.
- [ ] Step 4: run `pytest tests -q`. Expected: PASS.
- [ ] Step 5: `git init`, then commit `chore: scaffold ThreatDesk with ported runtime modules`.

### Task 2: Inventory sources

**Files:**
- Create: `threatdesk/inventory.py`, `config/tech-stack.template.csv` (header from spec decision 9 + 3 synthetic rows)
- Test: `tests/test_inventory.py`

**Interfaces:**
- Produces:
  - `load_assets() -> list[dict]`, with the same asset shape `vulns` uses, incl. `subcategory` and `patched_through`.
  - `sources_status() -> list[dict]` (`{name, configured, path, count, errors}`, one each for `csv`, `json`, `env`, and `servicenow` = not configured).
  - `save_csv(data: bytes) -> dict`, which replaces `config/tech-stack.csv` and keeps a `.bak`.
  - CSV path: `THREATDESK_TECH_STACK_CSV`, default `config/tech-stack.csv`.

- [ ] Step 1: tests:
  - `test_csv_parse` (`match` "a;b" → `["a","b"]`, `internet_facing` "yes" → True)
  - `test_bad_rows_skipped` (missing product → in `errors`, good rows load)
  - `test_bom_header`
  - `test_precedence_csv_over_json` (same vendor+product+version: the CSV owner wins)
  - `test_env_terms_product_only`
  - `test_save_csv_keeps_bak`
- [ ] Step 2: run. Expected: FAIL.
- [ ] Step 3: implement with `csv.DictReader`, reading with `utf-8-sig`.
- [ ] Step 4: run. Expected: PASS.
- [ ] Step 5: commit `feat(inventory): tech-stack CSV/JSON/env sources with ServiceNow slot`.

### Task 3: Vulns + threat feed

**Files:**
- Copy and trim: `threatdesk/vulns.py` (`load_inventory` delegates to `inventory.load_assets`), `threatdesk/threat_feed.py` (UA `ThreatDesk/0.1`)
- Test: port `tests/test_vulns.py` and adjust imports and env names

**Interfaces:**
- Produces: the `vulns.search/detail/inventory_view/vuln_news/set_tracking` signatures, unchanged from SOCbox. `threat_feed.get_feed(force: bool) -> dict`, unchanged.

- [ ] Step 1: port the tests. Add `test_threatdesk_env_names` (`THREATDESK_TECH_STACK` is honored).
- [ ] Step 2: run. Expected: FAIL.
- [ ] Step 3: copy and adapt.
- [ ] Step 4: run. Expected: PASS.
- [ ] Step 5: commit `feat(vulns): port vulnerability intel and threat feed`.

### Task 4: Triage orchestrator + agent

**Files:**
- Copy and trim: `threatdesk/triage_orchestrator.py` (remove the Primus path, functions `_run_triage_primus` and `_primus_*`, and the "promote" text; rebrand the system prompt; use the runtime `triage_model` and `cyber_fallback_enabled`)
- Copy and edit: `.claude/agents/threat-triage.md`:
  - Remove the Primus step, the legacy in-incident section and `memory: project`.
  - Set `model: claude-opus-5-5`.
  - Change the environment curl to `http://127.0.0.1:${THREATDESK_PORT:-8444}/api/environment`.
  - Add the rule: web searches use threat terms only.
- Copy any other `.claude/scripts/*` the agent references (excluding primus)
- Test: `tests/test_triage.py`

**Interfaces:**
- Produces:
  - `new_triage_id()`, `list_triages()`, `read_triage(id)`, `delete_triage(id)`, `rename_triage(id, name)`, `subscribe`/`unsubscribe`, and `_run_triage(id)`. `TRIAGES_DIR = REPO_ROOT/"triages"`.
  - `safe_attachment_name(name: str) -> str` (basename only, no `..`).

- [ ] Step 1: tests:
  - `test_lifecycle_fake_runner` (monkeypatch the runner to emit two events + session_complete; status goes queued → running → complete; `events.jsonl` has the lines)
  - `test_safe_attachment_name` (`"../../x.exe"` → `"x.exe"`)
  - `test_no_primus_symbols`
- [ ] Step 2: run. Expected: FAIL.
- [ ] Step 3: implement.
- [ ] Step 4: run. Expected: PASS.
- [ ] Step 5: commit `feat(triage): port triage orchestrator and threat-triage agent, Claude only`.

### Task 5: TIP (triage-only)

**Files:**
- Copy and trim: `threatdesk/tip_catalog.py` (`build_catalog(triages_dir)`, no `related_incidents`), `threatdesk/tip_enrichers.py`, `threatdesk/tip_misp.py` (rewritten: `event_for_triage(triage: dict) -> dict`)
- Test: `tests/test_tip.py`

**Interfaces:**
- Produces: `build_catalog(triages_dir: Path) -> list[dict]` and `event_for_triage(detail: dict) -> dict` (a MISP Event JSON with one Attribute per IOC; type mapping as in the SOCbox `tip_misp`).

- [ ] Step 1: tests:
  - `test_catalog_from_triages` (2 synthetic triages sharing a domain → 1 record, observation_count 2)
  - `test_misp_event_for_triage` (sha256 + domain → 2 attributes with MISP types `sha256` and `domain`)
- [ ] Step 2: run. Expected: FAIL.
- [ ] Step 3: implement.
- [ ] Step 4: run. Expected: PASS.
- [ ] Step 5: commit `feat(tip): IOC catalog and MISP export from triages`.

### Task 6: API app + server entry

**Files:**
- Create: `api/__init__.py`, `api/main.py`. Port the routes listed in the spec from SOCbox `api/main.py`, minus promote and `/api/llm/*`, plus `/api/inventory/sources` (GET) and `/api/inventory/csv` (PUT). `/api/environment` GET includes `inventory: load_assets()`, and `/api/tip/misp-export` takes `?triage_id=`.
- Create: `threatdesk/serve.py`. `main()` runs uvicorn on `127.0.0.1:THREATDESK_PORT`, and the app serves `web-dist/` with an SPA fallback.
- Test: `tests/test_api_smoke.py`

- [ ] Step 1: smoke tests with `TestClient`, one per route group, network monkeypatched:
  - `test_vulns_empty_inventory`
  - `test_environment_fallback_example`
  - `test_feed_upstream_down_returns_200`
  - `test_triage_create_hashes_attachment` (with a fake runner)
  - `test_tip_iocs`
  - `test_inventory_sources_lists_servicenow_unconfigured`
  - `test_runtime_settings_roundtrip`
- [ ] Step 2: run. Expected: FAIL.
- [ ] Step 3: implement.
- [ ] Step 4: run. Expected: PASS (and the full `pytest -q` passes).
- [ ] Step 5: commit `feat(api): slim FastAPI app with triage, vulns, feed, TIP, settings routes`.

### Task 7: Frontend

**Files:**
- Create the `web/` scaffold: `package.json` (deps trimmed to what's imported), `vite.config.ts` (proxy to 8444, outDir `../web-dist`), tailwind/postcss/tsconfig, `index.html`, `src/main.tsx`, and `src/App.tsx` with a router: `/` → redirect `/vulns`, `/vulns`, `/triage`, `/intel`, `/settings`.
- Create `src/shell/Shell.tsx`: a top bar with the ThreatDesk wordmark and four tabs, using the SOCbox tokens.
- Copy: `features/triage/*`, `features/vulns/*`, `features/threat-intel/*`, `features/settings/{AISettingsPanel,ServiceKeysCard}.tsx`, `hooks/useTriageStream.ts`, the needed `kit/*`, `components/ui/{dialog,toast,tabs}`, `lib/{cn,defang,format,aiConfig}`, `styles/*`, and `api/{client,types}.ts` trimmed to the routes that exist.
- Changes:
  - Remove the promote UI and Primus picker from TriageView.
  - Reword the incident-origin copy in ThreatIntelView.
  - The env hint references the Settings → Environment page.
  - New `features/settings/SettingsView.tsx` holds AI, service keys, an environment profile form (org name, SIEM preference, crown jewels) and inventory sources with CSV upload.
- Test: port `VulnsView.test.tsx`, plus `TriageView.deeplink.test.tsx`.

- [ ] Step 1: write the deeplink test (render at `/triage?threat=CVE-2026-0001`, input contains the CVE).
- [ ] Step 2: `npm install`, then `npm test`. Expected: FAIL.
- [ ] Step 3: implement.
- [ ] Step 4: `npm test` PASS, then `npm run build` (no type errors; `web-dist/` produced).
- [ ] Step 5: commit `feat(web): standalone ThreatDesk UI (Vulns, Triage, Intel, Settings)`.

### Task 8: End-to-end verification, docs, GitHub

- [ ] Step 1: `threatdesk` serving on 8444, with SOCbox not running. In the browser:
  - Vulns loads KEV with the template CSV inventory.
  - CVE detail opens, and tracking saves.
  - The feed rail renders on Triage.
  - A real triage (threat name) streams to completion.
  - Its IOCs appear in Intel, and the MISP export downloads.
  - Settings saves the environment and uploads a CSV.
- [ ] Step 2: side-by-side parity check against the SOCbox Vulns/Triage tabs for the same CVE and threat. Note every difference in `docs/PARITY.md` (intended removals listed).
- [ ] Step 3: write `README.md` (install, prerequisites: Python 3.11, Node 20, Claude Code CLI, curl, jq; first run; the pre-production note on `--dangerously-skip-permissions`), plus `docs/TECH-STACK.md`, `docs/SERVICENOW.md` and `docs/DEPENDENCIES.md` (every SOCbox coupling found and how it was replaced).
- [ ] Step 4: `pytest -q`, `npm test` and `npm run build` all pass. Then commit `docs: README, tech-stack, ServiceNow seam, parity`.
- [ ] Step 5: `gh repo create threatdesk --private --source . --push`.
