# ThreatDesk

Agent-driven threat triage and an exploited-vulnerability dashboard, matched to your technology inventory. It runs on a single machine.

ThreatDesk was carved out of SOC-in-a-Box (2026-11-18). It contains SOC-in-a-Box's Threat Triage, Vulnerabilities, Threat Feed and Intel (TIP) capabilities. There are no incidents, no CSIRT agents and no endpoint tooling. Nothing imports from or calls SOC-in-a-Box, and `tests/test_isolation.py` enforces this.

| Tab | What it answers |
|---|---|
| **Vulns** | Which actively exploited vulnerabilities (CISA KEV) hit **our** stack, where, owned by whom, and how exposed. It also shows what's new and loud right now (recent KEV additions, exploitation news), search by product / CVE / ATT&CK technique, and per-CVE detail with NVD, EPSS and remediation tracking. |
| **Triage** | Hand it a URL, pasted text, a file, or a threat name. The `threat-triage` agent researches it and streams back a report with key findings, IOCs, SIEM hunt queries, detections and recommended actions. Optionally it cross-references the org inventory. The live threat-feed rail on the right is a one-click source of inputs. |
| **Intel** | Every IOC from every triage, de-duplicated and searchable. You can enrich it on demand (VirusTotal, URLhaus, ThreatFox, AbuseIPDB) and export it to MISP, either per triage or in bulk. |
| **Settings** | Technology inventory (tech-stack CSV upload), environment profile, triage model and billing, threat-intel API keys, AI providers. |

## Install on a demo machine (Windows 10/11)

**1. Get the code.** The repo is private, so sign in to GitHub on that machine first. Use either option:

- **With git:** run `gh auth login` (or sign in through Git for Windows), then:
  ```powershell
  git clone https://github.com/jaxdeformity/threatdesk.git ThreatDesk
  cd ThreatDesk
  ```
- **Without git:** on github.com/jaxdeformity/threatdesk, use **Code → Download ZIP**, extract it, and open a terminal in the folder.

**2. Install.**

```powershell
.\install.cmd -Demo -InstallPrereqs
```

- `-Demo` loads the bundled synthetic Fortune-50 inventory, so the Vulns tab is full on first launch.
- `-InstallPrereqs` uses winget to install anything missing: Python 3.12, jq, Node LTS and the Claude Code CLI. Leave it off if those are already installed.

The installer creates `.venv`, installs ThreatDesk, writes `.env`, and adds `Start-ThreatDesk.cmd` plus a **ThreatDesk** desktop shortcut. It then opens http://127.0.0.1:8444.

The UI ships prebuilt in `web-dist/`, so the demo machine does not need Node unless you rebuild the UI.

**3. Sign the triage agent in (once).** Either option works:
- Run `claude` in a terminal and log in with a Claude account.
- Paste an Anthropic API key into **Settings → AI providers**.

Vulns, Intel and the threat feed work without this. Only Triage needs it.

**4. Demo.** Start it any time from the desktop shortcut. To update the demo machine later, run `git pull`, then `.\install.cmd -NoLaunch`.

| Option | Effect |
|---|---|
| `-Demo` | Inventory = `samples/meridian-global.csv` |
| `-InstallPrereqs` | winget/npm install of missing prerequisites |
| `-Port 9000` | Serve on another port (default 8444) |
| `-NoLaunch` | Install only |
| `-NoShortcut` | No desktop shortcut |

Network needs: outbound HTTPS to CISA, FIRST (EPSS), NIST NVD, the news RSS feeds, and Anthropic (for triage). Behind a proxy, set `HTTPS_PROXY` before installing and launching.

### Prerequisites the installer checks

- Python 3.11+
- [Claude Code CLI](https://docs.claude.com/claude-code) (`npm i -g @anthropic-ai/claude-code`). The triage agent runs through it.
- `jq` (`winget install jqlang.jq`) and `curl` (ships with Windows). The agent uses both.
- Node 20+ only if you rebuild the UI.

## Developer setup

```powershell
python -m pip install -e .[test]
cd web; npm install; npm run build; cd ..   # rebuild web-dist/ and commit it after UI changes
copy .env.example .env
threatdesk --open                           # http://127.0.0.1:8444
```

The port is `THREATDESK_PORT`, default 8444, so it runs alongside SOC-in-a-Box on 8443. For hot reload, run `threatdesk --reload` in one shell and `cd web; npm run dev` in another. Vite serves on :5173 and proxies `/api` to :8444.

## Model access and billing

Default: the triage agent inherits `ANTHROPIC_API_KEY` (or Bedrock/Vertex variables) from the server process. Set the key in **Settings → AI providers** (it's encrypted at rest with Windows DPAPI) or in the real OS environment. `.env` never loads `ANTHROPIC_*`.

If there's no key, the agent runs on whatever Claude account the CLI is logged in to. **Settings → Triage agent → "Run on the logged-in Claude subscription"** forces that mode even when a key is present.

Triage defaults to `claude-opus-5-5`. You can retry refused turns on a fallback model. That's off by default, and only useful where your account holds a cyber-use exemption.

## Telling it what you run

Vulns matching and triage's "cross-reference with our environment" both read one inventory (`threatdesk/inventory.py`). These sources are listed in precedence order:

1. **Tech-stack CSV.** One uploaded in Settings (stored at `config/tech-stack.csv`, which then wins), else the file named by `THREATDESK_TECH_STACK_CSV`. Start from `config/tech-stack.template.csv`. See [docs/TECH-STACK.md](docs/TECH-STACK.md).
2. **Inventory JSON** (`THREATDESK_INVENTORY`), `{"assets": [...]}`.
3. **Product list:** `THREATDESK_TECH_STACK="Microsoft Exchange, Fortinet FortiOS"`.
4. **ServiceNow CMDB.** The slot exists but there's no adapter yet. See [docs/SERVICENOW.md](docs/SERVICENOW.md).

A synthetic Fortune-50 inventory ("Meridian Global", fictional, 285 products) ships in `samples/` for demos. Set `THREATDESK_TECH_STACK_CSV=samples/meridian-global.csv`.

## Data on disk (all gitignored)

| Path | What |
|---|---|
| `triages/<TRG-id>/` | `input.json` (with SHA-256 of every attachment), `attachments/`, `events.jsonl` (append-only stream), `report.md`, `result.json`, `status.json` |
| `config/vuln_tracking.json` | Remediation status, owner, ticket, notes, history per CVE. Each record carries `provider` / `external_ref` for a future ServiceNow sync. |
| `config/cache/` | KEV / EPSS / NVD / news cache |
| `tip/enrichment/` | IOC enrichment cache (24 h) |
| `config/environment.json`, `config/runtime-settings.json`, `config/ai_config.json`, `config/service_keys.json` | Settings |
| `logs/` | Per-triage debug logs |

Outbound requests send only CVE ids, IOC values and search words. Inventory matching happens locally. The triage agent is told never to put org names, hostnames or asset details into web searches. When "cross-reference with our environment" is ticked, the inventory is sent to the model provider as context.

## Before production (known demo shortcuts)

- The agent runs Claude Code with `--dangerously-skip-permissions`. Replace it with an explicit allowed-tools list (WebFetch, WebSearch, Read/Write under `triages/<id>/`, Bash for `curl` / `jq` / `sha256sum`). Enterprise-managed Claude Code settings may disable bypass mode, and then every triage fails at launch.
- There's no auth, and it's single-user by design. It binds to `127.0.0.1` only.
- The Windows DPAPI key store makes it Windows-only.

## Tests

```powershell
python -m pytest -q          # backend + isolation guard
cd web; npm test; npm run build
```

See [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) for every SOC-in-a-Box coupling and what replaced it, and [docs/PARITY.md](docs/PARITY.md) for the parity check against SOC-in-a-Box.
