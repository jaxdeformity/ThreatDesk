# ServiceNow: the seam (not built in v1)

ThreatDesk v1 reads the org inventory from the tech-stack doc. Two places are shaped so a ServiceNow integration plugs in without touching the Vulns logic.

## 1. Inventory source (read: CMDB → inventory)

`threatdesk/inventory.py` merges sources into one list of asset dicts:

```
id, category, subcategory, vendor, product, version, patched_through,
environment, count, owner, criticality, internet_facing, match[]
```

A ServiceNow adapter would:

- implement `load() -> list[dict]` returning that shape, and add it to the merge in `load_assets()` (decide its precedence relative to the CSV).
- report itself in `sources_status()` (today the `servicenow` row is a fixed "not configured" slot), with `configured`, `count`, `errors`.
- read credentials from the environment (`SERVICENOW_INSTANCE`, `SERVICENOW_USER`/`SERVICENOW_PASSWORD` or OAuth client), never from the repo. Add the names to the `envfile` allowlist or the Service keys catalog.

Likely tables (Table API, `GET /api/now/table/<table>`):

| ThreatDesk field | ServiceNow source |
|---|---|
| vendor, product, version | `cmdb_sam_sw_install` / `cmdb_ci_spkg` (`manufacturer`, `name`, `version`), or SAM Pro `samp_sw_product` |
| count | count of installs per (product, version) |
| environment | `cmdb_ci.environment` / location of the installed-on CI |
| owner | `cmdb_ci.support_group` or `owned_by` |
| criticality | `cmdb_ci.business_criticality` (map 1 → crown_jewel … 4 → low) or the business service's criticality |
| internet_facing | CI attribute or a tag/relationship to an internet-facing service (instance specific) |
| patched_through | not native; derive from the version's release / patch date, or leave blank |
| match | from a mapping table (vendor/product → KEV names) maintained in ThreatDesk |

Pull it on a schedule into a local cache file and have `load()` read the cache, so Vulns never waits on ServiceNow.

## 2. Remediation tracking (write: ThreatDesk → tickets)

`config/vuln_tracking.json` keeps one record per CVE: status, owner, ticket, notes and history. Each record already carries `provider` and `external_ref`. A sync job can make ServiceNow (Vulnerability Response `sn_vul_vulnerable_item`, or incident/change records) the owner of `status`. In that case, set `provider: "servicenow"` and `external_ref: <sys_id or number>`, and have the job overwrite the local status from ServiceNow.

Writing into an enterprise's ServiceNow needs its field mappings and change approval. Agree on both with the instance owner before building this.

## 3. MCP (agent-side)

If the enterprise runs a ServiceNow MCP server, the triage agent can query it directly. For example, it could check whether the affected CI exists. Register the server in **Settings → AI providers → MCP servers** and add a line to `.claude/agents/threat-triage.md` saying when to use it. This needs no ThreatDesk code.
