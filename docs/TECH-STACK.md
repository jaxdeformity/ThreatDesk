# The tech-stack doc

ThreatDesk matches CISA KEV entries against what the org runs. It is only as good as this list. Start from `config/tech-stack.template.csv` (Settings → Technology inventory → **Template**), fill one row per product/version you run, and upload it.

## Columns

| Column | Required | Meaning / effect on matching |
|---|---|---|
| `id` | no | Your asset/product id. Auto-filled (`CSV-0002`, …) when blank. |
| `category`, `subcategory` | no | Grouping on the Vulns inventory strip (e.g. `Network` / `Remote access VPN`). |
| `vendor` | recommended | Vendor as KEV spells it (`Fortinet`, `Microsoft`, `Ivanti`). |
| `product` | **yes** | Product name. Rows without it are skipped and reported. |
| `version` | recommended | Deployed version; shown on cards and used for de-dup. |
| `patched_through` | recommended | `YYYY-MM-DD` fix level of the deployed version. A KEV entry added on or before this date is shown as **"Fixed in deployed version"** instead of open exposure. Blank = assume open. |
| `environment` | no | Where it runs (`prod`, `DMZ`, `6 data centres`). |
| `count` | no | Number of instances/hosts. Drives "N assets" and ranking. |
| `owner` | no | Team or mailbox that owns remediation. |
| `criticality` | no | `crown_jewel`, `high`, `medium` (default), `low`. Crown jewels rank first. |
| `internet_facing` | no | `yes`/`no`. Internet-facing exposure ranks higher. |
| `match` | recommended | Semicolon-separated names **CISA KEV** uses for this product, e.g. `Citrix NetScaler ADC;Citrix NetScaler Gateway`. Blank = `"<vendor> <product>"`. KEV naming is inconsistent; this column is how you make matching exact. |

A `match` phrase hits a KEV entry when it reads inside the KEV "vendor product" string, or when its first word is the KEV vendor and the rest starts the KEV product name. "Microsoft Exchange" matches *Exchange Server*, not *Internet Key Exchange*.

## Rules

- The file is UTF-8 (a BOM from Excel is fine).
- Uploading replaces `config/tech-stack.csv`. The previous file is kept as `tech-stack.csv.bak`.
- A file without a `product` column is rejected. Bad rows are skipped, the good rows still load, and the skipped rows are listed in Settings.
- If the same vendor + product + version also appears in the inventory JSON or the `.env` list, the CSV row wins.

`samples/meridian-global.csv` is a full worked example: 285 products for a fictional Fortune-50 group.
