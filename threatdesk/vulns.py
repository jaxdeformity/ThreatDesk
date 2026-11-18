"""Vulnerability intelligence for the Vulnerabilities tab.

What it answers:
  - Which actively exploited vulnerabilities touch *our* technology?
    The org's stack comes from ``threatdesk.inventory`` (tech-stack CSV,
    inventory JSON, or the THREATDESK_TECH_STACK comma list).
  - What is new and loud right now? KEV additions in the last 14 days,
    plus CVEs the news feeds keep mentioning (``threat_feed``).
  - Search by technology, CVE id or ATT&CK technique.
  - Detail for one CVE: KEV entry, NVD description and CVSS, EPSS
    exploit probability, news mentions, and where remediation stands.

Sources (public; the NVD key is optional, from ``NVD_API_KEY``):
  - CISA Known Exploited Vulnerabilities catalog (JSON), 6 h TTL
  - FIRST EPSS API, per-CVE, 24 h TTL
  - NIST NVD CVE API 2.0, per-CVE and keyword search, 24 h TTL

Remediation tracking is stored locally in ``config/vuln_tracking.json``
(status, owner, ticket, notes, history). It is the seam for a ServiceNow
(or Jira) sync later: each record carries ``provider`` and
``external_ref`` so a sync job can own the status instead of a human.

Requests send only CVE ids and search words. No org data leaves the
machine: the tech-stack match happens locally.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from threatdesk import inventory

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACKING_PATH = REPO_ROOT / "config" / "vuln_tracking.json"
CACHE_DIR = REPO_ROOT / "config" / "cache"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "ThreatDesk/0.1"

KEV_TTL = 6 * 3600
DETAIL_TTL = 24 * 3600
HOT_DAYS = 14

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)

# ATT&CK techniques that are about exploiting a vulnerability, mapped to
# the vulnerability language that tends to describe them. KEV entries do
# not carry technique ids, so this is a "related by type" match and the
# UI says so.
TECHNIQUE_TERMS: dict[str, dict[str, Any]] = {
    "T1190": {"name": "Exploit Public-Facing Application",
              "terms": ["remote code execution", "unauthenticated", "authentication bypass", "path traversal",
                        "sql injection", "command injection", "deserialization", "server-side request forgery"]},
    "T1133": {"name": "External Remote Services",
              "terms": ["vpn", "ssl vpn", "remote access", "gateway", "citrix", "pulse", "globalprotect", "fortios", "rdp"]},
    "T1210": {"name": "Exploitation of Remote Services",
              "terms": ["smb", "remote desktop", "rpc", "netlogon", "print spooler", "remote code execution"]},
    "T1068": {"name": "Exploitation for Privilege Escalation",
              "terms": ["privilege escalation", "elevation of privilege", "local privilege", "kernel"]},
    "T1203": {"name": "Exploitation for Client Execution",
              "terms": ["browser", "chrome", "webkit", "office", "word", "excel", "pdf", "use-after-free", "type confusion"]},
    "T1211": {"name": "Exploitation for Defense Evasion",
              "terms": ["security feature bypass", "smartscreen", "mark of the web", "bypass"]},
    "T1212": {"name": "Exploitation for Credential Access",
              "terms": ["credential", "ntlm", "hash disclosure", "information disclosure", "kerberos"]},
    "T1189": {"name": "Drive-by Compromise",
              "terms": ["browser", "chromium", "webkit", "javascript engine", "v8"]},
    "T1195": {"name": "Supply Chain Compromise",
              "terms": ["supply chain", "backdoor", "malicious code", "embedded malicious"]},
}

DONE_STATES = ("patched", "mitigated", "not_affected", "risk_accepted")
TRACK_STATES = ("not_started", "investigating", "in_progress", "mitigated", "patched", "not_affected", "risk_accepted")


# ── Cache helpers ────────────────────────────────────────────────────

_lock = threading.Lock()
_mem: dict[str, tuple[float, Any]] = {}


def _cached(key: str, ttl: int, fetch: Callable[[], Any]) -> Any:
    now = time.time()
    with _lock:
        hit = _mem.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    disk = CACHE_DIR / (re.sub(r"[^A-Za-z0-9_.-]", "_", key) + ".json")
    try:
        if disk.exists() and now - disk.stat().st_mtime < ttl:
            val = json.loads(disk.read_text(encoding="utf-8"))
            with _lock:
                _mem[key] = (disk.stat().st_mtime, val)
            return val
    except (OSError, ValueError):
        pass
    try:
        val = fetch()
    except Exception as e:  # noqa: BLE001
        log.warning("vulns: fetch %s failed: %s", key, e)
        # Stale beats nothing.
        if hit:
            return hit[1]
        try:
            return json.loads(disk.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise e
    with _lock:
        _mem[key] = (now, val)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        disk.write_text(json.dumps(val), encoding="utf-8")
    except OSError:
        pass
    return val


def _get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https hosts)
        return json.loads(r.read().decode("utf-8"))


# ── Sources ──────────────────────────────────────────────────────────

def kev_catalog() -> list[dict[str, Any]]:
    data = _cached("kev", KEV_TTL, lambda: _get_json(KEV_URL, timeout=30))
    # Same list object until the catalog refreshes, so the inventory index
    # (keyed on it) is built once per refresh, not once per request.
    if _kev_list.get("src") is not data:
        _kev_list.update(src=data, list=[v for v in (data or {}).get("vulnerabilities", []) if isinstance(v, dict)])
    return _kev_list["list"]


_kev_list: dict[str, Any] = {"src": None, "list": []}


def epss(cves: list[str]) -> dict[str, dict[str, float]]:
    """EPSS score and percentile per CVE. Batched, cached per CVE."""
    out: dict[str, dict[str, float]] = {}
    missing = []
    for c in {c.upper() for c in cves}:
        with _lock:
            hit = _mem.get("epss:" + c)
        if hit and time.time() - hit[0] < DETAIL_TTL:
            if hit[1]:
                out[c] = hit[1]
        else:
            missing.append(c)
    for i in range(0, len(missing), 80):
        chunk = missing[i:i + 80]
        try:
            data = _get_json(EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)}), timeout=15)
        except Exception as e:  # noqa: BLE001
            log.warning("vulns: EPSS failed: %s", e)
            break
        got = {}
        for row in data.get("data", []):
            try:
                got[row["cve"].upper()] = {"score": float(row["epss"]), "percentile": float(row["percentile"])}
            except (KeyError, ValueError, TypeError):
                continue
        now = time.time()
        with _lock:
            for c in chunk:
                _mem["epss:" + c] = (now, got.get(c))
        out.update(got)
    return out


def _nvd_headers() -> dict[str, str]:
    k = os.environ.get("NVD_API_KEY")
    return {"apiKey": k} if k else {}


def nvd_cve(cve: str) -> dict[str, Any] | None:
    cve = cve.upper()

    def fetch() -> Any:
        d = _get_json(NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve}), _nvd_headers())
        items = d.get("vulnerabilities") or []
        return _nvd_summary(items[0]["cve"]) if items else None
    try:
        return _cached("nvd_" + cve, DETAIL_TTL, fetch)
    except Exception:  # noqa: BLE001
        return None


def nvd_search(keyword: str, limit: int = 20) -> list[dict[str, Any]]:
    kw = keyword.strip()[:80]

    def fetch() -> Any:
        q = {"keywordSearch": kw, "resultsPerPage": str(limit), "noRejected": ""}
        d = _get_json(NVD_URL + "?" + urllib.parse.urlencode(q), _nvd_headers())
        return [_nvd_summary(v["cve"]) for v in d.get("vulnerabilities") or []]
    try:
        return _cached("nvdq_" + kw.lower(), DETAIL_TTL, fetch) or []
    except Exception:  # noqa: BLE001
        return []


def _nvd_summary(c: dict[str, Any]) -> dict[str, Any]:
    desc = next((d.get("value") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    cvss = None
    metrics = c.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                cvss = {"score": data.get("baseScore"), "severity": data.get("baseSeverity") or m.get("baseSeverity"),
                        "vector": data.get("vectorString"), "version": data.get("version")}
                break
        if cvss:
            break
    cwes = sorted({d.get("value") for w in c.get("weaknesses") or [] for d in w.get("description") or []
                   if str(d.get("value", "")).startswith("CWE-")})
    products = set()
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) > 5 and m.get("vulnerable"):
                    products.add(f"{parts[3]} {parts[4]}".replace("_", " "))
    return {
        "cve": c.get("id"), "published": c.get("published"), "modified": c.get("lastModified"),
        "description": desc, "cvss": cvss, "cwes": cwes, "products": sorted(products)[:12],
        "references": [r.get("url") for r in (c.get("references") or [])[:12] if r.get("url")],
        "status": c.get("vulnStatus"),
    }


# ── Org inventory ────────────────────────────────────────────────────
#
# Sources and precedence live in threatdesk.inventory (tech-stack CSV >
# inventory JSON > THREATDESK_TECH_STACK list). Synthetic demo inventory:
# samples/meridian-global.{json,csv}.

CRIT_ORDER = {"crown_jewel": 0, "high": 1, "medium": 2, "low": 3}


def org_stack() -> list[str]:
    """Plain product terms from THREATDESK_TECH_STACK (SOC_ORG_TECH_STACK accepted)."""
    return inventory.env_terms()


def _inventory_path() -> Path | None:
    """The file-backed inventory source shown in the UI: the tech-stack CSV
    when present, else the inventory JSON."""
    c = inventory.csv_path()
    return c if c.exists() else inventory.json_path()


_inv_cache: dict[str, Any] = {"key": None, "assets": []}


def load_inventory() -> list[dict[str, Any]]:
    """Merged org inventory (tech-stack CSV > inventory JSON > env list)."""
    assets = inventory.load_assets()
    key = inventory.cache_key()
    if _inv_cache["key"] != key:
        _inv_cache.update(key=key, assets=assets, index=None)
    return assets


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


_ALIASES = {"chrome": "chromium", "netscaler": "netscaler", "exchange": "exchange server"}


def _phrase_hits(phrase: str, vendor: str, product: str) -> bool:
    """``vendor`` and ``product`` already normalised. A phrase matches when
    it reads inside "vendor product", or its first word is the vendor and
    the rest starts the product name, or (one word) it is the vendor or
    starts the product."""
    words = _norm(phrase).split()
    if not words:
        return False
    if f" {' '.join(words)} " in f" {vendor} {product} ":
        return True
    if len(words) >= 2 and vendor and words[0] in vendor.split():
        rest = [_ALIASES.get(w, w).split()[0] for w in words[1:]]
        if product.split()[:len(rest)] == rest:
            return True
    return len(words) == 1 and (words[0] == vendor or product.startswith(words[0] + " ") or product == words[0])


def stack_match(v: dict[str, Any], stack: list[str]) -> str | None:
    """First plain stack term matching a KEV entry. "Microsoft Exchange"
    matches Exchange Server, not "Internet Key Exchange"."""
    vendor, product = _norm(v.get("vendorProject", "")), _norm(v.get("product", ""))
    return next((t for t in stack if _phrase_hits(t, vendor, product)), None)


def inventory_matches(v: dict[str, Any], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vendor, product = _norm(v.get("vendorProject", "")), _norm(v.get("product", ""))
    return [a for a in assets if any(_phrase_hits(m, vendor, product) for m in a.get("match") or [])]


def _index(kev: list[dict[str, Any]], assets: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """CVE -> matching inventory records, memoised per catalog + inventory."""
    key = (id(kev), len(kev), _inv_cache.get("key"), id(assets), len(assets))
    if _inv_cache.get("index_key") == key and _inv_cache.get("index") is not None:
        return _inv_cache["index"]
    idx = {}
    for v in kev:
        hits = inventory_matches(v, assets)
        if hits:
            idx[str(v.get("cveID", "")).upper()] = hits
    _inv_cache.update(index=idx, index_key=key)
    return idx


def _asset_brief(a: dict[str, Any]) -> dict[str, Any]:
    return {k: a.get(k) for k in ("id", "category", "subcategory", "vendor", "product", "version", "environment",
                                  "count", "owner", "criticality", "internet_facing", "patched_through")}


def _is_open(a: dict[str, Any], date_added: str | None) -> bool:
    """The deployed version does not cover this KEV entry. ``patched_through``
    is the fix level of the version in production; unknown means open."""
    pt = a.get("patched_through")
    return not pt or not date_added or str(date_added) > str(pt)


def _exposure(hits: list[dict[str, Any]], date_added: str | None = None) -> dict[str, Any] | None:
    if not hits:
        return None
    open_hits = [a for a in hits if _is_open(a, date_added)]
    covered = not open_hits
    hits = sorted(open_hits or hits, key=lambda a: (CRIT_ORDER.get(a.get("criticality"), 9), -(a.get("count") or 0)))
    top = hits[0]
    label = " ".join(x for x in (top.get("product"), top.get("version")) if x)
    return {
        "label": label,
        "assets": [_asset_brief(a) for a in hits[:8]],
        "products": len(hits),
        "asset_count": sum(a.get("count") or 0 for a in hits) or None,
        "crown_jewel": any(a.get("criticality") == "crown_jewel" for a in hits),
        "internet_facing": any(a.get("internet_facing") for a in hits),
        "owners": sorted({a.get("owner") for a in hits if a.get("owner")})[:6],
        "covered": covered,
        "covered_note": ("The deployed version already includes the fix." if covered else None),
    }


def inventory_view(kev: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Every inventory record with how many known-exploited CVEs hit it
    and how many of those are still open."""
    kev = kev if kev is not None else kev_catalog()
    assets = load_inventory()
    idx = _index(kev, assets)
    tracking = _load_tracking()
    by_asset: dict[str, list[str]] = {}
    for cve, hits in idx.items():
        for a in hits:
            by_asset.setdefault(a.get("id") or a["product"], []).append(cve)
    rows = []
    for a in assets:
        cves = by_asset.get(a.get("id") or a["product"], [])
        added = {str(v.get("cveID", "")).upper(): v.get("dateAdded") for v in kev}
        open_ = [c for c in cves if _is_open(a, added.get(c)) and (tracking.get(c) or {}).get("status") not in DONE_STATES]
        rows.append({**_asset_brief(a), "kev": len(cves), "open": len(open_)})
    path = _inventory_path()
    return {"source": str(path.relative_to(REPO_ROOT)) if path and path.is_relative_to(REPO_ROOT) else (str(path) if path else None),
            "assets": rows}


# ── Tracking ─────────────────────────────────────────────────────────

def _load_tracking() -> dict[str, Any]:
    try:
        d = json.loads(TRACKING_PATH.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def get_tracking(cve: str) -> dict[str, Any] | None:
    return _load_tracking().get(cve.upper())


def set_tracking(cve: str, status: str, owner: str = "", ticket: str = "", note: str = "",
                 by: str = "analyst") -> dict[str, Any]:
    cve = cve.upper()
    if not CVE_RE.match(cve):
        raise ValueError("not a CVE id")
    if status not in TRACK_STATES:
        raise ValueError(f"status must be one of {', '.join(TRACK_STATES)}")
    with _lock:
        data = _load_tracking()
        rec = data.get(cve) or {"cve": cve, "provider": "local", "external_ref": None, "history": []}
        now = datetime.now(timezone.utc).isoformat()
        rec["history"] = (rec.get("history") or [])[-49:] + [{
            "at": now, "by": by, "status": status, "note": note[:500],
        }]
        rec.update({"status": status, "owner": owner[:80], "ticket": ticket[:120], "updated_at": now})
        data[cve] = rec
        TRACKING_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = TRACKING_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        tmp.replace(TRACKING_PATH)
    return rec


# ── Cards and search ─────────────────────────────────────────────────

def _card(v: dict[str, Any], idx: dict[str, list], news: dict[str, int], tracking: dict[str, Any]) -> dict[str, Any]:
    cve = str(v.get("cveID", "")).upper()
    t = tracking.get(cve) or {}
    exp = _exposure(idx.get(cve) or [], v.get("dateAdded"))
    return {
        "cve": cve,
        "title": v.get("vulnerabilityName") or cve,
        "vendor": v.get("vendorProject") or "",
        "product": v.get("product") or "",
        "summary": v.get("shortDescription") or "",
        "kev": True,
        "date_added": v.get("dateAdded"),
        "due_date": v.get("dueDate"),
        "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
        "org_match": exp["label"] if exp else None,
        "exposure": exp,
        "news_mentions": news.get(cve, 0),
        "tracking": t.get("status"),
    }


def _nvd_card(n: dict[str, Any], assets: list[dict[str, Any]], news: dict[str, int], tracking: dict[str, Any]) -> dict[str, Any]:
    cve = str(n.get("cve", "")).upper()
    t = tracking.get(cve) or {}
    prods = n.get("products") or []
    vendor, _, product = (prods[0].partition(" ") if prods else ("", "", ""))
    hits = [h for p in prods for h in inventory_matches({"vendorProject": p.partition(" ")[0], "product": p.partition(" ")[2]}, assets)]
    exp = _exposure(list({id(h): h for h in hits}.values()))
    return {
        "cve": cve, "title": (n.get("description") or cve)[:120], "vendor": vendor, "product": product,
        "summary": n.get("description") or "", "kev": False, "date_added": None, "due_date": None,
        "published": n.get("published"), "ransomware": False, "org_match": exp["label"] if exp else None,
        "exposure": exp,
        "news_mentions": news.get(cve, 0), "tracking": t.get("status"),
        "cvss": n.get("cvss"),
    }


def _rank(c: dict[str, Any]) -> tuple:
    e = c.get("exposure") or {}
    return (0 if c["org_match"] and not e.get("covered") and c.get("tracking") not in DONE_STATES else 1,
            0 if c["org_match"] else 1, 0 if e.get("crown_jewel") else 1, 0 if e.get("internet_facing") else 1,
            0 if c["kev"] else 1, 0 if c.get("ransomware") else 1,
            "" if not c.get("date_added") else _inv(c["date_added"]), -(c.get("news_mentions") or 0))


def _inv(d: str) -> str:
    try:
        return str(99999999 - int(d.replace("-", "")[:8]))
    except ValueError:
        return "z"


def search(q: str = "", scope: str = "all", news: dict[str, int] | None = None, limit: int = 60,
           kev: list[dict[str, Any]] | None = None, use_nvd: bool = True) -> dict[str, Any]:
    """scope: all | org | hot. ``q`` is a technology, CVE id or technique."""
    kev = kev if kev is not None else kev_catalog()
    assets = load_inventory()
    idx = _index(kev, assets)
    news = news or {}
    tracking = _load_tracking()
    q = (q or "").strip()
    mode = "browse"
    cards: list[dict[str, Any]] = []
    note = ""

    if q and CVE_RE.match(q):
        mode = "cve"
        hits = [v for v in kev if str(v.get("cveID", "")).upper() == q.upper()]
        if hits:
            cards = [_card(hits[0], idx, news, tracking)]
        elif use_nvd:
            n = nvd_cve(q)
            cards = [_nvd_card(n, assets, news, tracking)] if n else []
            note = "" if cards else "No record for that CVE in KEV or NVD."
    elif q and TECHNIQUE_RE.match(q):
        mode = "technique"
        tid = q.upper().split(".")[0]
        spec = TECHNIQUE_TERMS.get(tid)
        if spec:
            terms = spec["terms"]
            for v in kev:
                text = _norm(f"{v.get('vulnerabilityName', '')} {v.get('shortDescription', '')} {v.get('product', '')}")
                if any(_norm(t) in text for t in terms):
                    cards.append(_card(v, idx, news, tracking))
            note = (f"{tid} {spec['name']}: known exploited vulnerabilities of the kind this technique uses. "
                    "Matched by vulnerability type, not a CISA mapping.")
        else:
            note = f"{tid} is not an exploitation technique, so no vulnerabilities map to it."
    elif q:
        mode = "text"
        words = _norm(q).split()
        for v in kev:
            text = _norm(f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')} "
                         f"{v.get('shortDescription', '')} {v.get('cveID', '')}")
            if all(w in text for w in words):
                cards.append(_card(v, idx, news, tracking))
        if use_nvd and len(cards) < 12:
            seen = {c["cve"] for c in cards}
            for n in nvd_search(q):
                if n.get("cve") and n["cve"].upper() not in seen:
                    cards.append(_nvd_card(n, assets, news, tracking))
            if any(not c["kev"] for c in cards):
                note = "Includes NVD results that are not on the known-exploited list."
    else:
        cards = [_card(v, idx, news, tracking) for v in kev]

    cutoff = (datetime.now(timezone.utc) - timedelta(days=HOT_DAYS)).date().isoformat()
    if scope == "org":
        cards = [c for c in cards if c["org_match"]]
        if not q:
            cards = [c for c in cards if not (c.get("exposure") or {}).get("covered") and c.get("tracking") not in DONE_STATES]
    elif scope == "hot":
        cards = [c for c in cards if (c.get("date_added") or "") >= cutoff or c["news_mentions"] >= 2]

    cards.sort(key=_rank)
    total = len(cards)
    cards = cards[:limit]
    scores = epss([c["cve"] for c in cards]) if cards and use_nvd else {}
    for c in cards:
        c["epss"] = scores.get(c["cve"])

    org_all = [v for v in kev if str(v.get("cveID", "")).upper() in idx]
    hot_all = [v for v in kev if (v.get("dateAdded") or "") >= cutoff]
    def _open_hits(v: dict[str, Any]) -> list[dict[str, Any]]:
        return [a for a in idx[str(v.get("cveID", "")).upper()] if _is_open(a, v.get("dateAdded"))]
    covered = [v for v in org_all if not _open_hits(v)]
    open_org = [v for v in org_all if _open_hits(v)
                and (tracking.get(str(v.get("cveID", "")).upper()) or {}).get("status") not in DONE_STATES]
    exposed = {a.get("id") or a.get("product") for hits in idx.values() for a in hits}
    cats: dict[str, dict[str, int]] = {}
    for a in assets:
        c = cats.setdefault(a.get("category") or "Other", {"products": 0, "exposed": 0})
        c["products"] += 1
        c["exposed"] += 1 if (a.get("id") or a.get("product")) in exposed else 0
    today = datetime.now(timezone.utc).date().isoformat()
    return {
        "mode": mode, "query": q, "scope": scope, "note": note, "total": total, "items": cards,
        "stack": [a["product"] for a in assets if a.get("category") == "Listed in .env"],
        "inventory": {"products": len(assets), "exposed": len(exposed),
                      "categories": [{"name": k, **v} for k, v in sorted(cats.items(), key=lambda kv: -kv[1]["exposed"])]},
        "counts": {
            "kev_total": len(kev), "org_affected": len(org_all), "org_open": len(open_org),
            "hot": len(hot_all),
            "ransomware": sum(1 for v in open_org if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"),
            "covered_by_version": len(covered),
            "crown_jewel": sum(1 for v in open_org if any(a.get("criticality") == "crown_jewel" for a in _open_hits(v))),
            "internet_facing": sum(1 for v in open_org if any(a.get("internet_facing") for a in _open_hits(v))),
            "overdue": sum(1 for v in open_org if v.get("dueDate") and v["dueDate"] < today),
        },
    }


def detail(cve: str, news_items: list[dict[str, Any]] | None = None, kev: list[dict[str, Any]] | None = None,
           use_net: bool = True) -> dict[str, Any] | None:
    cve = cve.upper()
    if not CVE_RE.match(cve):
        return None
    kev = kev if kev is not None else kev_catalog()
    k = next((v for v in kev if str(v.get("cveID", "")).upper() == cve), None)
    n = nvd_cve(cve) if use_net else None
    if not k and not n:
        return None
    assets = load_inventory()
    if k:
        hits = inventory_matches(k, assets)
    else:
        hits = [h for p in (n or {}).get("products") or []
                for h in inventory_matches({"vendorProject": p.partition(" ")[0], "product": p.partition(" ")[2]}, assets)]
    exp = _exposure(list({id(h): h for h in hits}.values()), (k or {}).get("dateAdded"))
    mentions = [{"title": i.get("title"), "url": i.get("link") or i.get("url"), "source": i.get("source_name") or i.get("source"),
                 "published": i.get("published")}
                for i in news_items or [] if cve in [c.upper() for c in i.get("cves") or []]][:8]
    return {
        "cve": cve,
        "title": (k or {}).get("vulnerabilityName") or (n or {}).get("description", cve)[:120],
        "kev": {
            "vendor": k.get("vendorProject"), "product": k.get("product"), "date_added": k.get("dateAdded"),
            "due_date": k.get("dueDate"), "required_action": k.get("requiredAction"),
            "description": k.get("shortDescription"), "ransomware": str(k.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "notes": k.get("notes"), "cwes": k.get("cwes") or [],
        } if k else None,
        "nvd": n,
        "epss": (epss([cve]) if use_net else {}).get(cve),
        "org_match": exp["label"] if exp else None,
        "exposure": exp,
        "news": mentions,
        "tracking": get_tracking(cve),
        "links": {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" if k else None,
            "mitre": f"https://www.cve.org/CVERecord?id={cve}",
        },
    }


def news_mentions(feed: dict[str, Any] | None) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """CVE -> number of distinct news items mentioning it."""
    items = (feed or {}).get("items") or []
    counts: dict[str, int] = {}
    for it in items:
        for c in {str(c).upper() for c in it.get("cves") or []}:
            counts[c] = counts.get(c, 0) + 1
    return counts, items


# ── Vulnerability news ───────────────────────────────────────────────
#
# CISA's alerts feed refuses Python HTTP clients and Rapid7's feed is not
# well-formed XML, so neither is a source. CISA's signal comes straight
# from the KEV catalog instead: every addition in the last 14 days is a
# story, since an addition means CISA has evidence of exploitation.
#
# A vulnerability-only feed: research and advisory sources that publish
# about vulnerabilities being exploited, plus the Triage feed's items that
# name a CVE. Each story is tagged with the CVEs it mentions, whether
# they are on KEV, whether they hit the org inventory, and whether the
# text reports exploitation.

VULN_SOURCES = [
    {"id": "watchtowr", "name": "watchTowr Labs", "url": "https://labs.watchtowr.com/rss/", "tier": "research"},
    {"id": "tenable", "name": "Tenable", "url": "https://www.tenable.com/blog/feed", "tier": "research"},
    {"id": "horizon3", "name": "Horizon3.ai", "url": "https://horizon3.ai/feed/", "tier": "research"},
    {"id": "helpnet-vulns", "name": "Help Net Security", "url": "https://www.helpnetsecurity.com/tag/vulnerability/feed/", "tier": "news"},
    {"id": "securityweek-vulns", "name": "SecurityWeek", "url": "https://www.securityweek.com/category/vulnerabilities/feed/", "tier": "news"},
]
NEWS_TTL = 30 * 60
_EXPLOITED_RE = re.compile(r"\b(exploited|exploiting|exploitation|exploits|in the wild|zero[- ]days?|0-days?|"
                           r"actively|under attack|mass[- ]exploit\w*|ransomware|threat actors?|"
                           r"hackers (?:target|exploit|hit|abuse)\w*|added to (?:the )?KEV|known exploited)\b", re.I)
_VULN_WORDS_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|vulnerabilit(?:y|ies)|zero[- ]days?|0-days?|exploit\w*|patch(?:es|ed)?|flaws?|"
                            r"remote code execution|RCE|authentication bypass|advisory)\b", re.I)
_CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _fetch_vuln_sources() -> list[dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor
    from threatdesk import threat_feed

    def one(src: dict[str, str]) -> list[dict[str, Any]]:
        try:
            return threat_feed._fetch_source(src)
        except Exception as e:  # noqa: BLE001
            log.warning("vulns: news source %s failed: %s", src["id"], e)
            return []
    with ThreadPoolExecutor(max_workers=len(VULN_SOURCES)) as ex:
        out = [it for items in ex.map(one, VULN_SOURCES) for it in items]
    if not out:
        raise RuntimeError("no vulnerability news source responded")
    return out


def vuln_news_items(feed_items: list[dict[str, Any]] | None = None, cached_only: bool = False) -> list[dict[str, Any]]:
    """Raw items from the vulnerability sources (30 min cache) plus
    vulnerability-related items from the Triage feed."""
    items: list[dict[str, Any]] = []
    if cached_only:
        with _lock:
            hit = _mem.get("vuln_news")
        items = list(hit[1]) if hit else []
    else:
        try:
            items = list(_cached("vuln_news", NEWS_TTL, _fetch_vuln_sources))
        except Exception:  # noqa: BLE001
            items = []
    for it in feed_items or []:
        text = f"{it.get('title', '')} {it.get('summary', '')}"
        if it.get("cves") or _VULN_WORDS_RE.search(text):
            items.append(it)
    return items


_GENERIC_VENDORS = {"apache", "google", "microsoft", "apple", "oracle", "cisco", "ibm", "red hat", "meta", "php",
                    "git", "linux", "android", "arm", "rails", "vite", "pear", "nx", "daemon", "sudo",
                    "isc", "exim", "plex", "cleo", "wazuh", "erlang"}


def _mention_terms(assets: list[dict[str, Any]]) -> list[tuple[re.Pattern[str], str]]:
    """Vendor and product names worth spotting in a headline without a
    CVE. Big platform vendors are matched by product, not vendor name, so
    "Microsoft" in a headline does not flag every Microsoft product."""
    terms: dict[str, str] = {}
    for a in assets:
        v = str(a.get("vendor") or "").strip()
        if v and v.lower() not in _GENERIC_VENDORS and len(v) > 2:
            terms.setdefault(re.split(r"\s*\(", v)[0], v)
        for m in a.get("match") or []:
            words = str(m).split()
            if len(words) >= 2 and words[0].lower() in _GENERIC_VENDORS:
                prod = " ".join(words[1:])
                if len(prod) > 3 and not prod.lower().startswith(("multiple", "windows ", "kernel")):
                    terms.setdefault(prod, f"{words[0]} {prod}")
    return [(re.compile(r"\b" + re.escape(t) + r"\b", re.I), label) for t, label in terms.items()]


def vuln_news(feed_items: list[dict[str, Any]] | None = None, mine: bool = False, limit: int = 60,
              kev: list[dict[str, Any]] | None = None, raw: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    kev = kev if kev is not None else kev_catalog()
    kev_by = {str(v.get("cveID", "")).upper(): v for v in kev}
    assets = load_inventory()
    idx = _index(kev, assets)
    tracking = _load_tracking()
    mention_terms = _mention_terms(assets)
    raw = raw if raw is not None else vuln_news_items(feed_items)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HOT_DAYS)).date().isoformat()
    kev_items = []
    for v in kev:
        added = v.get("dateAdded") or ""
        if added < cutoff:
            continue
        cve = str(v.get("cveID", "")).upper()
        try:
            ts = datetime.fromisoformat(added).replace(tzinfo=timezone.utc).timestamp() + 43200
        except ValueError:
            ts = 0
        kev_items.append({
            "title": f"CISA confirms exploitation: {v.get('vulnerabilityName') or cve} ({cve})",
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}", "source_name": "CISA KEV",
            "published": added, "published_ts": ts, "summary": v.get("shortDescription") or "", "cves": [cve],
            "_kev_addition": True,
        })
    raw = kev_items + list(raw)
    seen: set[str] = set()
    out = []
    for it in raw:
        title = re.sub(r"\s+", " ", str(it.get("title") or "")).strip()
        key = (it.get("link") or title).lower()
        if not title or key in seen:
            continue
        seen.add(key)
        text = f"{title} {it.get('summary', '')}"
        cves = sorted({c.upper() for c in list(it.get("cves") or []) + _CVE_FIND.findall(text)})
        if not cves and not _VULN_WORDS_RE.search(text):
            continue
        tags = []
        for c in cves[:12]:
            k = kev_by.get(c)
            hits = idx.get(c) or []
            exp = _exposure(hits, (k or {}).get("dateAdded")) if hits else None
            tags.append({"cve": c, "kev": bool(k), "in_stack": bool(exp),
                         "open": bool(exp and not exp["covered"] and (tracking.get(c) or {}).get("status") not in DONE_STATES),
                         "product": exp["label"] if exp else None})
        summary = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(it.get("summary") or ""))).strip()
        mentions = sorted({label for rx, label in mention_terms if rx.search(title)})[:5]
        out.append({
            "title": title,
            "link": it.get("link"),
            "source": it.get("source_name") or it.get("source") or "",
            "published": it.get("published"),
            "ts": it.get("published_ts") or 0,
            "summary": summary[:240] + ("…" if len(summary) > 240 else ""),
            "cves": tags,
            "exploited": bool(it.get("_kev_addition")) or bool(_EXPLOITED_RE.search(text)) or any(t["kev"] for t in tags),
            "kev_addition": bool(it.get("_kev_addition")),
            "in_stack": any(t["in_stack"] for t in tags) or bool(mentions),
            "open_in_stack": any(t["open"] for t in tags),
            "mentions": mentions,
        })
    if mine:
        out = [o for o in out if o["in_stack"]]
    out.sort(key=lambda o: -(o["ts"] or 0))
    return {
        "items": out[:limit],
        "total": len(out),
        "sources": ["CISA KEV"] + [s["name"] for s in VULN_SOURCES],
        "counts": {"exploited": sum(1 for o in out if o["exploited"]),
                   "open_in_stack": sum(1 for o in out if o["open_in_stack"])},
    }
