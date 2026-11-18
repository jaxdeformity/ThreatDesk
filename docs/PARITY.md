# Parity check against SOC-in-a-Box (2026-11-18)

Method: ThreatDesk served on :8444 with SOC-in-a-Box **not running**. Same synthetic inventory on both sides: Meridian Global, 285 products. SOCbox read it from `scenarios/org-inventory/meridian-global.json` through its own `soc_in_a_box.vulns`, called in-process. ThreatDesk read it from `samples/meridian-global.csv` through HTTP. Same live KEV catalog (1,782 entries).

## Vulns

| Check | SOC-in-a-Box | ThreatDesk | Match |
|---|---|---|---|
| Inventory products | 285 | 285 | yes |
| Products with KEV history | 241 | 241 | yes |
| Open KEV exposures (sum) | 174 | 174 | yes |
| "Open in your estate" total | 148 | 148 | yes (first 10 identical, same order) |
| Hot now (KEV added ≤14 d) | 15 | 15 | same CVE set; order differs only because the in-process SOCbox call was given no news counts, while the API ranks by news mentions in both products |
| Search `fortinet` | 32 | 32 | yes |
| Search `T1190` | 839 | 839 | yes |
| Search `CVE-2024-3400` | 1 | 1 | yes |
| CVE detail CVE-2024-3400 | KEV + NVD + EPSS + exposure | same fields, `org_match` = PA-7080 / PA-5450 (PAN-OS) 11.1.4-h7 | yes |

The UI renders the same dashboard: 148 open, 33 crown-jewel, 88 internet-facing, 143 past fix-by, 8 ransomware, 15 new. It shows the category strip, the card grid and the vulnerability news rail. There are no console errors.

## Threat feed

`/api/threats/feed`: 96 items from 9 sources (8 of 9 reachable on this run), 11 topics, KEV cross-reference loaded. The Triage tab shows the feed rail.

## Triage

A live run on `CVE-2024-3400` with use_environment on and SIEM Splunk. The agent read its role file, read `input.json`, and pulled the org profile and inventory from `http://127.0.0.1:8444/api/environment` (ThreatDesk's own port). It then researched vendor advisories and wrote `report.md` + `result.json`. Result: see the end-to-end note in the commit that adds this file.

## Intentional differences

- No Primus model picker or badge. Claude only.
- No "Create incident". The button is now **MISP export** for that triage.
- The Intel catalog is built from triages only.
- Settings holds only what ThreatDesk uses: inventory, environment profile, triage agent, service keys and AI providers.
- Uploaded triage attachments are SHA-256 hashed into `input.json`. SOCbox did not hash them on intake.
- Agent billing defaults to the configured API key. SOCbox defaulted to the Max subscription.
