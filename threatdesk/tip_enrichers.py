"""TIP enrichment adapters.

Given a (type, value) IOC, fan out to external intel sources and
return a normalized enrichment payload the UI can render. Results are
cached on disk under ``tip/enrichment/`` with a 24-hour TTL so
re-viewing a known IOC doesn't burn API quota.

Enrichers in v1:

  - VirusTotal v3  , files (hashes), ip_addresses, domains, urls
                      requires env VT_API_KEY
  - URLhaus        . URL + hash lookup (abuse.ch)
                      requires env ABUSECH_API_KEY (free, auth.abuse.ch)
  - ThreatFox      . IOC search (abuse.ch)
                      requires env ABUSECH_API_KEY (same key)
  - MalwareBazaar  . sample metadata by hash (abuse.ch)
                      requires env ABUSECH_API_KEY (same key)
  - Feodo Tracker  . botnet C2 IP blocklist (abuse.ch)
                      requires env ABUSECH_API_KEY (same key)
  - AbuseIPDB      . IPv4 reputation, requires env ABUSEIPDB_API_KEY

Each enricher implements ``supports(ioc_type)`` and ``fetch(value)``.
The orchestrator runs supported enrichers in parallel and merges
results into a single dict keyed by enricher name.

All network calls are stdlib-only (urllib + json) so there are no
new Python deps. Timeout is strict (8s per call), enrichment is
best-effort, not load-bearing.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


log = logging.getLogger(__name__)


TIMEOUT_S = 8
CACHE_TTL_S = 24 * 3600  # 24h
USER_AGENT = "ThreatDesk-TIP/0.1"


# ── Base ──────────────────────────────────────────────────────────────

@dataclass
class EnricherStatus:
    name: str
    configured: bool
    requires_key: bool
    env_var: str | None
    supports: list[str]
    notes: str = ""


class Enricher:
    name: str = "base"
    requires_key: bool = False
    env_var: str | None = None
    notes: str = ""
    supported_types: tuple[str, ...] = ()

    def configured(self) -> bool:
        if not self.requires_key:
            return True
        return bool(self.env_var and os.environ.get(self.env_var))

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    def status(self) -> EnricherStatus:
        return EnricherStatus(
            name=self.name,
            configured=self.configured(),
            requires_key=self.requires_key,
            env_var=self.env_var,
            supports=list(self.supported_types),
            notes=self.notes,
        )

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


# ── VirusTotal ────────────────────────────────────────────────────────

class VirusTotalEnricher(Enricher):
    name = "virustotal"
    requires_key = True
    env_var = "VT_API_KEY"
    notes = "Premium API keys unlock richer data; free keys are rate-limited to ~4 req/min."
    supported_types = ("sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return {"error": "VT_API_KEY not set"}
        base = "https://www.virustotal.com/api/v3"
        if ioc_type in ("sha256", "sha1", "md5"):
            url = f"{base}/files/{urllib.parse.quote(value)}"
        elif ioc_type in ("ipv4", "ipv6"):
            url = f"{base}/ip_addresses/{urllib.parse.quote(value)}"
        elif ioc_type == "domain":
            url = f"{base}/domains/{urllib.parse.quote(value)}"
        elif ioc_type == "url":
            # VT URL IDs are url-safe base64 of the URL (no padding)
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            url = f"{base}/urls/{url_id}"
        else:
            return {"error": f"VT does not support type {ioc_type!r}"}
        req = urllib.request.Request(url, headers={
            "x-apikey": api_key,
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False, "message": "Not in VirusTotal"}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        # Compact, human-meaningful projection
        return {
            "found": True,
            "link": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(value)}",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()) if stats else None,
            "reputation": attrs.get("reputation"),
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "first_submission_date": attrs.get("first_submission_date"),
            "times_submitted": attrs.get("times_submitted"),
            "tags": attrs.get("tags"),
            "categories": attrs.get("categories"),
            "signature_info": attrs.get("signature_info"),
        }


# ── URLhaus ───────────────────────────────────────────────────────────

class URLhausEnricher(Enricher):
    name = "urlhaus"
    requires_key = True
    env_var = "ABUSECH_API_KEY"
    notes = "abuse.ch URLhaus. URL/host/hash lookup for distributing malware. Free Auth-Key, register at auth.abuse.ch."
    supported_types = ("url", "domain", "sha256", "md5")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return {"error": "ABUSECH_API_KEY not set (register free at auth.abuse.ch)"}
        # URLhaus v1 uses POST form-encoded with a "url" / "host" / "sha256_hash" / "md5_hash" field
        endpoint_map = {
            "url":     ("https://urlhaus-api.abuse.ch/v1/url/",    "url"),
            "domain":  ("https://urlhaus-api.abuse.ch/v1/host/",   "host"),
            "sha256":  ("https://urlhaus-api.abuse.ch/v1/payload/", "sha256_hash"),
            "md5":     ("https://urlhaus-api.abuse.ch/v1/payload/", "md5_hash"),
        }
        ep = endpoint_map.get(ioc_type)
        if not ep:
            return {"error": f"URLhaus does not support type {ioc_type!r}"}
        url, field = ep
        body = urllib.parse.urlencode({field: value}).encode()
        req = urllib.request.Request(url, data=body, headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Auth-Key": api_key,
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        status = data.get("query_status")
        if status != "ok":
            return {"found": False, "status": status}
        # Shape depends on endpoint; project a common subset
        out: dict[str, Any] = {
            "found": True,
            "link": data.get("urlhaus_reference"),
            "threat": data.get("threat") or data.get("threat_type"),
            "tags": data.get("tags"),
            "date_added": data.get("date_added") or data.get("firstseen"),
            "last_online": data.get("last_online"),
        }
        if "payloads" in data:
            out["payload_count"] = len(data.get("payloads") or [])
        if "urls" in data:
            out["url_count"] = len(data.get("urls") or [])
        if "signature" in data:
            out["signature"] = data.get("signature")
        return out


# ── ThreatFox ─────────────────────────────────────────────────────────

class ThreatFoxEnricher(Enricher):
    name = "threatfox"
    requires_key = True
    env_var = "ABUSECH_API_KEY"
    notes = "abuse.ch ThreatFox. IOC repository across hashes, IPs, domains, URLs. Free Auth-Key, register at auth.abuse.ch."
    supported_types = ("sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return {"error": "ABUSECH_API_KEY not set (register free at auth.abuse.ch)"}
        # ThreatFox: POST JSON {"query":"search_ioc","search_term":value}
        body = json.dumps({"query": "search_ioc", "search_term": value}).encode()
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Auth-Key": api_key,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        if data.get("query_status") != "ok":
            return {"found": False, "status": data.get("query_status")}
        rows = data.get("data") or []
        if not rows:
            return {"found": False}
        # Take the richest single match (highest confidence)
        best = max(rows, key=lambda r: int(r.get("confidence_level") or 0))
        return {
            "found": True,
            "match_count": len(rows),
            "malware": best.get("malware_printable") or best.get("malware"),
            "malware_alias": best.get("malware_alias"),
            "threat_type": best.get("threat_type"),
            "confidence_level": best.get("confidence_level"),
            "first_seen": best.get("first_seen"),
            "last_seen": best.get("last_seen"),
            "reporter": best.get("reporter"),
            "tags": best.get("tags"),
            "link": f"https://threatfox.abuse.ch/browse.php?search={urllib.parse.quote(value)}",
        }


# ── AbuseIPDB ─────────────────────────────────────────────────────────

class AbuseIPDBEnricher(Enricher):
    name = "abuseipdb"
    requires_key = True
    env_var = "ABUSEIPDB_API_KEY"
    notes = "Community-reported IP abuse score. Free tier = 1000 checks/day."
    supported_types = ("ipv4", "ipv6")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return {"error": "ABUSEIPDB_API_KEY not set"}
        params = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90, "verbose": ""})
        url = f"https://api.abuseipdb.com/api/v2/check?{params}"
        req = urllib.request.Request(url, headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = (json.loads(raw.decode("utf-8")) or {}).get("data") or {}
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        return {
            "found": True,
            "link": f"https://www.abuseipdb.com/check/{urllib.parse.quote(value)}",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_public": data.get("isPublic"),
            "last_reported_at": data.get("lastReportedAt"),
        }


# ── MalwareBazaar (abuse.ch) ──────────────────────────────────────────

class MalwareBazaarEnricher(Enricher):
    name = "malwarebazaar"
    requires_key = True
    env_var = "ABUSECH_API_KEY"
    notes = "abuse.ch MalwareBazaar. Malware sample metadata by hash. Free Auth-Key, register at auth.abuse.ch."
    supported_types = ("sha256", "sha1", "md5")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return {"error": "ABUSECH_API_KEY not set (register free at auth.abuse.ch)"}
        body = urllib.parse.urlencode({"query": "get_info", "hash": value}).encode()
        req = urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Auth-Key": api_key,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        if data.get("query_status") != "ok":
            return {"found": False, "status": data.get("query_status")}
        rows = data.get("data") or []
        if not rows:
            return {"found": False}
        r = rows[0]
        return {
            "found": True,
            "link": f"https://bazaar.abuse.ch/sample/{r.get('sha256_hash','')}/",
            "file_type": r.get("file_type"),
            "file_size": r.get("file_size"),
            "signature": r.get("signature"),
            "tags": r.get("tags"),
            "delivery_method": r.get("delivery_method"),
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "reporter": r.get("reporter"),
            "origin_country": r.get("origin_country"),
            "intelligence_clamav": (r.get("intelligence") or {}).get("clamav"),
            "intelligence_downloads": (r.get("intelligence") or {}).get("downloads"),
            "sha256_hash": r.get("sha256_hash"),
            "sha1_hash": r.get("sha1_hash"),
            "md5_hash": r.get("md5_hash"),
            "imphash": r.get("imphash"),
        }


# ── Feodo Tracker (abuse.ch) ──────────────────────────────────────────

class FeodoTrackerEnricher(Enricher):
    """Feodo Tracker publishes a single JSON blocklist (all known C2
    IPs for Emotet, Dridex, TrickBot, QakBot, Bumblebee, PikaBot, etc).
    Cheap to pull and scan, we fetch once per 6h (shorter than the
    24h global cache) and keep it in-process, then do a membership
    check per IP."""
    name = "feodotracker"
    requires_key = True
    env_var = "ABUSECH_API_KEY"
    notes = "abuse.ch Feodo Tracker. IPs on the active botnet C2 blocklist. Free Auth-Key, register at auth.abuse.ch."
    supported_types = ("ipv4", "ipv6")

    _blocklist_cache: dict[str, dict[str, Any]] | None = None
    _blocklist_fetched_at: float = 0.0
    _BLOCKLIST_TTL = 6 * 3600   # 6h

    def _ensure_blocklist(self) -> dict[str, dict[str, Any]] | None:
        api_key = os.environ.get(self.env_var or "", "")
        if not api_key:
            return None
        now = time.time()
        if self._blocklist_cache is not None and (now - self._blocklist_fetched_at) < self._BLOCKLIST_TTL:
            return self._blocklist_cache
        try:
            req = urllib.request.Request(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json",
                    "Auth-Key": api_key,
                },
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
            data = json.loads(raw.decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        # Index by IP for O(1) membership check
        idx = {row.get("ip_address"): row for row in data if row.get("ip_address")}
        FeodoTrackerEnricher._blocklist_cache = idx
        FeodoTrackerEnricher._blocklist_fetched_at = now
        return idx

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        idx = self._ensure_blocklist()
        if idx is None:
            return {"error": "could not fetch Feodo Tracker blocklist"}
        row = idx.get(value)
        if not row:
            return {
                "found": False,
                "link": "https://feodotracker.abuse.ch/browse/",
                "note": f"not on active C2 blocklist (checked against {len(idx)} entries)",
            }
        return {
            "found": True,
            "link": "https://feodotracker.abuse.ch/browse/",
            "malware": row.get("malware"),
            "port": row.get("port"),
            "first_seen": row.get("first_seen"),
            "last_online": row.get("last_online"),
            "status": row.get("status"),
            "as_number": row.get("as_number"),
            "as_name": row.get("as_name"),
            "country": row.get("country"),
        }


# ── Shodan InternetDB (free, no auth) ─────────────────────────────────

class ShodanInternetDBEnricher(Enricher):
    """Shodan's InternetDB is an unauthenticated slice of their data,
    open ports, CPEs, known CVEs, hostnames, for any public IPv4.
    No API key, no rate limits published, but Shodan TOS applies."""
    name = "shodan_internetdb"
    requires_key = False
    notes = "Shodan InternetDB. IP open-ports, CPEs, CVEs, hostnames. Free, no auth."
    supported_types = ("ipv4",)

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        req = urllib.request.Request(
            f"https://internetdb.shodan.io/{urllib.parse.quote(value)}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False, "note": "IP not indexed by Shodan"}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        return {
            "found": True,
            "link": f"https://www.shodan.io/host/{urllib.parse.quote(value)}",
            "ports": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "cpes": data.get("cpes"),
            "vulns": data.get("vulns"),
            "tags": data.get("tags"),
        }


# ── CIRCL Hash Lookup (free, no auth) ─────────────────────────────────

class CirclHashLookupEnricher(Enricher):
    """CIRCL's hashlookup cross-references NIST NSRL + other known-
    benign sources. Used to rule out 'this hash is just a stock
    Windows DLL, stop investigating it.'"""
    name = "circl_hashlookup"
    requires_key = False
    notes = "CIRCL hashlookup, known-benign check against NSRL + public lists. Free, no auth."
    supported_types = ("sha256", "sha1", "md5")

    def fetch(self, ioc_type: str, value: str) -> dict[str, Any]:
        url = f"https://hashlookup.circl.lu/lookup/{ioc_type}/{urllib.parse.quote(value)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False, "note": "not in any CIRCL hashlookup dataset"}
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except (urllib.error.URLError, TimeoutError) as e:
            return {"error": str(e)}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {"error": f"bad response: {e}"}
        # CIRCL returns rich data when matched, project the actionable bits.
        return {
            "found": True,
            "known_benign": True,           # presence = this hash is in a known-good list
            "source": data.get("source"),
            "FileName": data.get("FileName"),
            "FileSize": data.get("FileSize"),
            "ProductCode": data.get("ProductCode"),
            "OpSystemCode": data.get("OpSystemCode"),
            "MfgCode": data.get("MfgCode"),
            "db": data.get("db") or data.get("dbnm"),
            "SpecialCode": data.get("SpecialCode"),
        }


# ── Orchestration ─────────────────────────────────────────────────────

ENRICHERS: list[Enricher] = [
    # Free, no-auth, always active
    URLhausEnricher(),
    ThreatFoxEnricher(),
    MalwareBazaarEnricher(),
    FeodoTrackerEnricher(),
    ShodanInternetDBEnricher(),
    CirclHashLookupEnricher(),
    # Optional premium, stays in the list but inactive until the user
    # supplies an API key. Listed last so they sort below the free ones.
    VirusTotalEnricher(),
    AbuseIPDBEnricher(),
]


def enricher_status() -> list[dict[str, Any]]:
    """Small surface for the UI, which enrichers are wired."""
    return [_status_dict(e.status()) for e in ENRICHERS]


def _status_dict(s: EnricherStatus) -> dict[str, Any]:
    return {
        "name": s.name,
        "configured": s.configured,
        "requires_key": s.requires_key,
        "env_var": s.env_var,
        "supports": s.supports,
        "notes": s.notes,
    }


async def enrich(
    ioc_type: str,
    value: str,
    cache_dir: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Run every supported enricher in parallel and return a merged dict.

    Each enricher's result lives under ``out[enricher.name]``. A
    ``meta`` key records which enrichers ran and their timing.
    """
    cache_path = _cache_path_for(cache_dir, ioc_type, value)
    if not force and cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if time.time() - cached.get("cached_at", 0) < CACHE_TTL_S:
                cached["from_cache"] = True
                return cached
        except (OSError, json.JSONDecodeError):
            pass

    active = [e for e in ENRICHERS if e.supports(ioc_type) and e.configured()]
    started = time.time()
    results: dict[str, Any] = {
        "type": ioc_type,
        "value": value,
        "cached_at": time.time(),
        "from_cache": False,
        "enrichers_run": [e.name for e in active],
        "enrichers_skipped": [
            e.name for e in ENRICHERS
            if e.supports(ioc_type) and not e.configured()
        ],
    }

    async def _run(e: Enricher) -> tuple[str, dict[str, Any], float]:
        start = time.time()
        try:
            data = await asyncio.to_thread(e.fetch, ioc_type, value)
        except Exception as exc:  # noqa: BLE001, never let one adapter break the fan-out
            data = {"error": f"unhandled: {exc}"}
        return e.name, data, time.time() - start

    tasks = [_run(e) for e in active]
    if tasks:
        completed = await asyncio.gather(*tasks, return_exceptions=False)
        for name, data, dur in completed:
            results[name] = data
            results.setdefault("timings", {})[name] = round(dur, 2)

    results["total_duration_s"] = round(time.time() - started, 2)

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    except OSError as e:
        log.warning("tip: failed to write enrichment cache %s: %s", cache_path, e)

    return results


def _cache_path_for(cache_dir: Path, ioc_type: str, value: str) -> Path:
    """Hash-based path so weird characters in the value (slashes,
    colons in IPv6) don't break the filesystem."""
    import hashlib
    h = hashlib.sha1(f"{ioc_type}:{value}".encode("utf-8")).hexdigest()[:16]
    return cache_dir / ioc_type / f"{h}.json"
