"""Threat-feed aggregator, pulls high-signal public security feeds
and correlates them so the Triage workbench can surface a "top industry
threats" rail without any external dependencies beyond stdlib.

Sources (all public, no auth, no paywall):

    - CISA Cybersecurity Advisories (Atom/RSS)
    - CISA Known Exploited Vulnerabilities (JSON catalog)
    - The Hacker News (RSS)
    - BleepingComputer (RSS)
    - Krebs on Security (RSS)
    - SANS Internet Storm Center. Handler Diaries (RSS)

Each source is fetched on a 30-minute TTL. Fetches are isolated:
one bad source doesn't tank the rail. CVE IDs are extracted from each
item's text so items referencing the same CVE cluster together. KEV
membership is flagged via the CISA KEV catalog.

Kept intentionally dependency-free: urllib + ElementTree + re.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from html import unescape
from typing import Any
from xml.etree import ElementTree as ET


log = logging.getLogger(__name__)


# ── Source table ──────────────────────────────────────────────────────

SOURCES: list[dict[str, str]] = [
    {
        "id": "cisa-csa",
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "tier": "gov",
    },
    {
        "id": "hackernews",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "tier": "news",
    },
    {
        "id": "bleeping",
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "tier": "news",
    },
    {
        "id": "krebs",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "tier": "analysis",
    },
    {
        "id": "sans-isc",
        "name": "SANS ISC",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "tier": "analysis",
    },
    # Cyber Security Hub (industry desk). A focused, high-signal subset of
    # https://www.cshub.com/rss-feeds — the news desk plus the three
    # category feeds that map to threat-ops work. The marketing feeds
    # (webinars, whitepapers, jobs, podcasts) are intentionally omitted.
    {
        "id": "cshub-news",
        "name": "CS Hub News",
        "url": "https://www.cshub.com/rss/news",
        "tier": "industry",
    },
    {
        "id": "cshub-attacks",
        "name": "CS Hub Attacks",
        "url": "https://www.cshub.com/rss/categories/attacks",
        "tier": "industry",
    },
    {
        "id": "cshub-malware",
        "name": "CS Hub Malware",
        "url": "https://www.cshub.com/rss/categories/malware",
        "tier": "industry",
    },
    {
        "id": "cshub-threat-defense",
        "name": "CS Hub Threat Defense",
        "url": "https://www.cshub.com/rss/categories/threat-defense",
        "tier": "industry",
    },
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TTL_SECONDS = 30 * 60          # 30 min
OUTAGE_BACKOFF_SECONDS = 120   # retry delay after every source failed
FETCH_TIMEOUT = 12              # seconds per source
USER_AGENT = "ThreatDesk/0.1"

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Light-weight malware-family heuristic, only a curated list; the goal
# is clustering (group items by family name when multiple sources talk
# about the same thing), not classification.
MALWARE_FAMILIES: list[str] = [
    "AgentTesla", "AsyncRAT", "Cobalt Strike", "Conti", "Emotet", "Gootloader",
    "GuLoader", "IcedID", "LockBit", "Lumma", "Medusa", "PikaBot", "Qakbot",
    "Raspberry Robin", "RedLine", "SocGholish", "Snake", "SnakeKeylogger",
    "Vidar", "XLoader", "ZLoader",
]
ACTOR_GROUPS: list[str] = [
    "APT28", "APT29", "APT41", "Cl0p", "FIN7", "Lazarus", "Mustang Panda",
    "Scattered Spider", "Storm-1811", "TA505", "UNC1234", "Volt Typhoon",
]


# Topic classifier. Each topic is a set of keywords/phrases; an item
# gets a topic tag if ANY of its patterns match title+summary case-
# insensitively. Multi-label, an item can belong to several topics.
# Patterns are matched as whole words / phrases (not substrings) so
# "apt" doesn't fire on "adapt".
TOPIC_KEYWORDS: dict[str, list[str]] = {
    "Zero-day": [
        r"zero[-\s]?day", r"\b0[-\s]?day\b", r"unpatched",
        r"actively exploited", r"in[-\s]the[-\s]wild",
    ],
    "Ransomware": [
        r"ransomware", r"ransom demand", r"extortion", r"leak site",
        r"double extortion", r"data-leak", r"encrypted files",
    ],
    "Supply Chain": [
        r"supply[-\s]chain", r"software supply", r"vendor compromise",
        r"third[-\s]party", r"dependency confusion", r"typosquat",
        r"\bnpm\b", r"\bpypi\b", r"rubygems", r"package repository",
        r"build system", r"ci/cd", r"malicious package",
    ],
    "Nation-State": [
        r"nation[-\s]state", r"state[-\s]sponsored", r"\bAPT\b",
        r"espionage campaign", r"geopolitical",
        # Also fires on specific known groups
        r"Lazarus", r"Volt Typhoon", r"Sandworm", r"Fancy Bear",
        r"Cozy Bear", r"Mustang Panda", r"Salt Typhoon",
    ],
    "Phishing": [
        r"phishing", r"spear[-\s]phish", r"vishing", r"smishing",
        r"credential harvest", r"business email compromise", r"\bBEC\b",
        r"ClickFix", r"fake login", r"impersonation",
    ],
    "Cloud": [
        r"\bAWS\b", r"Amazon Web Services", r"\bAzure\b", r"\bGCP\b",
        r"Google Cloud", r"Kubernetes", r"\bS3 bucket", r"cloud mis",
        r"serverless", r"IAM misconfig", r"container escape",
    ],
    "Critical Infra": [
        r"\bICS\b", r"\bOT\b security", r"\bSCADA\b", r"industrial control",
        r"power grid", r"water utility", r"pipeline", r"transportation sector",
        r"critical infrastructure", r"operational technology",
    ],
    "Data Breach": [
        r"data breach", r"records exposed", r"database leak",
        r"\bPII\b", r"personally identifiable", r"million.*records",
        r"breach notification", r"exposed online",
    ],
    "Vulnerability": [
        r"security advisory", r"patch (?:released|available|tuesday)",
        r"\bCVSS\b", r"vulnerability disclos", r"bug bounty",
        r"exploit proof[-\s]of[-\s]concept", r"\bPoC\b",
    ],
    "Law Enforcement": [
        r"indict(?:ed|ment)", r"\bFBI\b", r"\bCISA\b advisory",
        r"\bDOJ\b", r"sanctions", r"takedown", r"sentenced",
        r"arrested", r"extradit",
    ],
    "Malware": [
        r"malware", r"backdoor", r"trojan", r"stealer", r"info[-\s]stealer",
        r"\bRAT\b", r"rootkit", r"keylogger", r"wiper",
    ],
}

# Pre-compile patterns once.
_TOPIC_RX: dict[str, list[re.Pattern[str]]] = {
    topic: [re.compile(p, re.IGNORECASE) for p in patterns]
    for topic, patterns in TOPIC_KEYWORDS.items()
}


def _classify_topics(text: str) -> list[str]:
    """Return sorted list of topics that match the given text."""
    if not text:
        return []
    hits: list[str] = []
    for topic, patterns in _TOPIC_RX.items():
        if any(p.search(text) for p in patterns):
            hits.append(topic)
    return hits


# Topics the UI knows about, expose so the frontend can render a
# filter chip row without hardcoding the list.
TOPIC_ORDER: list[str] = list(TOPIC_KEYWORDS.keys())


# ── In-process cache ──────────────────────────────────────────────────

@dataclass
class FeedCache:
    items: list[dict[str, Any]] = field(default_factory=list)
    kev_cves: set[str] = field(default_factory=set)
    source_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_refreshed_at: float = 0.0
    last_failed_at: float = 0.0
    refreshing: bool = False


_cache = FeedCache()
_cache_lock = asyncio.Lock()


# ── Public API ────────────────────────────────────────────────────────

async def get_feed(force: bool = False) -> dict[str, Any]:
    """Return the current correlated feed. Refreshes on first call or
    when the TTL expires; subsequent calls within the TTL are cheap
    (just return the cached payload)."""
    now = time.time()
    # After a total outage, wait OUTAGE_BACKOFF before refetching so an
    # offline box doesn't pay every source's timeout on each request.
    backing_off = now - _cache.last_failed_at < OUTAGE_BACKOFF_SECONDS
    if force or (now - _cache.last_refreshed_at > TTL_SECONDS and not backing_off):
        async with _cache_lock:
            # Double-check under the lock, another caller may have
            # just refreshed while we waited.
            if force or time.time() - _cache.last_refreshed_at > TTL_SECONDS:
                await _refresh()
    return {
        "items": _cache.items,
        "sources": SOURCES,
        "source_status": _cache.source_status,
        "kev_cve_count": len(_cache.kev_cves),
        "last_refreshed_at": _cache.last_refreshed_at,
        "ttl_seconds": TTL_SECONDS,
        "topics": TOPIC_ORDER,
    }


# ── Refresh ───────────────────────────────────────────────────────────

async def _refresh() -> None:
    """Fetch all sources in parallel, extract primitives, correlate."""
    _cache.refreshing = True
    started = time.time()

    tasks = [asyncio.to_thread(_fetch_source, s) for s in SOURCES]
    kev_task = asyncio.to_thread(_fetch_kev)
    results = await asyncio.gather(*tasks, kev_task, return_exceptions=True)

    feed_results = results[:-1]
    kev_result = results[-1]

    # Merge all items
    items: list[dict[str, Any]] = []
    source_status: dict[str, dict[str, Any]] = {}
    for src, res in zip(SOURCES, feed_results):
        if isinstance(res, Exception):
            source_status[src["id"]] = {"ok": False, "error": str(res)[:200], "count": 0}
            log.warning("threat_feed: %s failed: %s", src["id"], res)
            continue
        source_status[src["id"]] = {"ok": True, "count": len(res), "error": None}
        items.extend(res)

    kev_cves: set[str] = set()
    if isinstance(kev_result, Exception):
        log.warning("threat_feed: KEV fetch failed: %s", kev_result)
    elif kev_result:
        kev_cves = kev_result

    # Total outage (offline demo box, proxy hiccup): keep serving the last
    # good feed, record the failures, and leave last_refreshed_at alone so
    # the next request retries instead of pinning an empty feed for a TTL.
    if not items and not any(s["ok"] for s in source_status.values()):
        _cache.source_status = source_status
        _cache.refreshing = False
        _cache.last_failed_at = time.time()
        log.warning("threat_feed: every source failed; keeping %d cached items", len(_cache.items))
        return

    # Correlation pass
    cve_index: dict[str, list[int]] = {}
    family_index: dict[str, list[int]] = {}
    for idx, it in enumerate(items):
        for cve in it.get("cves", []):
            cve_index.setdefault(cve, []).append(idx)
        for fam in it.get("malware_families", []):
            family_index.setdefault(fam, []).append(idx)

    for idx, it in enumerate(items):
        # Cross-source hubbub: number of distinct SOURCES (not items)
        # mentioning any CVE/family in this item. Excludes this item's
        # own source so a single source writing 3 articles doesn't
        # inflate its own hubbub.
        sources_mentioning: set[str] = set()
        for cve in it.get("cves", []):
            for other_idx in cve_index.get(cve, []):
                if other_idx == idx:
                    continue
                sources_mentioning.add(items[other_idx]["source_id"])
        for fam in it.get("malware_families", []):
            for other_idx in family_index.get(fam, []):
                if other_idx == idx:
                    continue
                sources_mentioning.add(items[other_idx]["source_id"])
        it["hubbub_score"] = len(sources_mentioning)
        it["correlated_sources"] = sorted(sources_mentioning)

        # KEV flag
        it_cves = set(it.get("cves", []))
        it["kev_cves"] = sorted(it_cves & kev_cves)
        it["is_kev"] = bool(it["kev_cves"])

    # ── Story clustering pass ─────────────────────────────────────────
    # Multiple sources will cover the same story ("CISA adds 8 flaws
    # to KEV" → Hacker News + BleepingComputer + CISA Advisories all
    # publish about it). Without clustering the feed shows all of
    # them as separate rows, which buries signal under dupes. Group
    # items into clusters and represent each cluster as ONE row with
    # a list of contributing source links.
    items = _cluster_stories(items)

    # Priority sort. KEV first, then hubbub score, then recency
    items.sort(
        key=lambda it: (
            1 if it.get("is_kev") else 0,
            it.get("hubbub_score", 0),
            it.get("published_ts") or 0,
        ),
        reverse=True,
    )

    # Cap at 120 items total (enough for several days of browsing)
    items = items[:120]

    _cache.items = items
    _cache.kev_cves = kev_cves
    _cache.source_status = source_status
    _cache.last_refreshed_at = time.time()
    _cache.refreshing = False
    log.info(
        "threat_feed: refreshed %d items across %d sources in %.1fs (KEV: %d CVEs)",
        len(items), sum(1 for s in source_status.values() if s["ok"]),
        time.time() - started, len(kev_cves),
    )


# ── Story clustering ──────────────────────────────────────────────────

# Tokens that are too generic to be part of a story-key, stripped
# before title-overlap matching.
_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "of", "for", "in", "on", "to", "at",
    "by", "with", "from", "as", "is", "are", "was", "were", "be", "been",
    "has", "have", "had", "can", "could", "will", "would", "its", "it's",
    "this", "that", "these", "those", "new", "says", "said", "after",
    "before", "about", "into", "over", "under", "up", "down", "now",
    "alert", "breaking", "report", "news", "update", "threat", "warning",
})


def _story_tokens(title: str) -> set[str]:
    """Extract meaningful tokens from a title for similarity matching.
    Lowercase, alphanumeric-only, 3+ chars, strip stopwords. Returns
    the set of distinct tokens. Two titles with 3+ shared tokens are
    probably about the same story."""
    if not title:
        return set()
    raw = re.findall(r"[a-z0-9]{3,}", title.lower())
    return {t for t in raw if t not in _STOPWORDS}


def _cluster_stories(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse items that are about the same story into one row with
    a list of source links for all members. Clustering signals (any
    of these merges two items):

    1. They share ≥1 CVE ID (strongest signal, same vuln coverage)
    2. They share ≥3 story-tokens in the title (title overlap)

    Uses union-find with path compression. The cluster's representative
    item is the one with the "best" title, currently "longest title
    from a gov-tier source if any, else longest title overall", since
    gov advisories tend to have the canonical framing.
    """
    n = len(items)
    if n <= 1:
        return items

    # Pre-compute story tokens for each item once.
    tokens = [_story_tokens(it.get("title", "")) for it in items]

    # Union-find
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Pass 1: merge items that share any CVE ID. Fastest + strongest.
    cve_to_idx: dict[str, list[int]] = {}
    for i, it in enumerate(items):
        for cve in it.get("cves") or []:
            cve_to_idx.setdefault(cve, []).append(i)
    for idxs in cve_to_idx.values():
        for i in idxs[1:]:
            union(idxs[0], i)

    # Pass 2: O(n²) title-similarity pass. Laptop-scale (n ≤ ~200) so
    # fine. For items already clustered via CVE we skip; only try to
    # merge items that are in different clusters.
    for i in range(n):
        for j in range(i + 1, n):
            if find(i) == find(j):
                continue
            shared = tokens[i] & tokens[j]
            if len(shared) >= 3:
                union(i, j)

    # Build clusters
    clusters: dict[int, list[int]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    # Emit one item per cluster with a merged "cluster_sources" field.
    out: list[dict[str, Any]] = []
    for idxs in clusters.values():
        # Pick the representative, prefer gov-tier, then longest title.
        def _score(i: int) -> tuple[int, int]:
            tier_rank = {"gov": 2, "analysis": 1, "news": 0}.get(
                items[i].get("source_tier", ""), 0,
            )
            return (tier_rank, len(items[i].get("title") or ""))
        rep_idx = max(idxs, key=_score)
        rep = dict(items[rep_idx])  # copy, we're adding fields

        # Cluster sources: for EVERY member item, one entry.
        rep_cluster_sources = []
        for i in idxs:
            member = items[i]
            rep_cluster_sources.append({
                "source_id": member.get("source_id"),
                "source_name": member.get("source_name"),
                "source_tier": member.get("source_tier"),
                "title": member.get("title"),
                "link": member.get("link"),
                "published_ts": member.get("published_ts"),
                "published": member.get("published"),
            })
        # Sort cluster sources newest-first so the expanded view is
        # chronological.
        rep_cluster_sources.sort(
            key=lambda s: s.get("published_ts") or 0, reverse=True,
        )
        rep["cluster_sources"] = rep_cluster_sources
        rep["cluster_size"] = len(idxs)

        # When clustered, newest published_ts across members wins
        # (user wants "freshest time the story was covered").
        newest = max(
            (s.get("published_ts") or 0 for s in rep_cluster_sources),
            default=0,
        )
        if newest:
            rep["published_ts"] = newest

        # Union CVEs + families + actors + topics across all members so
        # the tag row on the collapsed row shows the full picture.
        for field_name in ("cves", "malware_families", "actor_groups", "topics", "kev_cves"):
            merged_vals: set[str] = set()
            for i in idxs:
                for v in items[i].get(field_name) or []:
                    merged_vals.add(str(v))
            rep[field_name] = sorted(merged_vals)
        rep["is_kev"] = bool(rep.get("kev_cves"))

        out.append(rep)
    return out


# ── Per-source fetch (runs in a thread) ───────────────────────────────

def _fetch_source(src: dict[str, str]) -> list[dict[str, Any]]:
    """Fetch and parse one RSS/Atom feed. Returns a list of normalized
    item dicts. Raises on HTTP error so the caller can record it in
    source_status."""
    req = urllib.request.Request(src["url"], headers={
        # Some publishers (cisa.gov) refuse non-browser agents.
        "User-Agent": src.get("user_agent") or USER_AGENT,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
    })
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read()

    # Some feeds default to ISO-8859-1 headers, try UTF-8 first, fall
    # back to latin-1 for broken encodings.
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1", errors="replace")

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # HTML entities (&nbsp;, &rsquo;) are not defined in XML. Escape
        # any entity XML doesn't know and parse again.
        text = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", text)
        root = ET.fromstring(text)
    # RSS 2.0 channels have <item>; Atom has <entry>. Handle both.
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    items: list[dict[str, Any]] = []

    # RSS
    for el in root.iter("item"):
        items.append(_parse_rss_item(el, src))
        if len(items) >= 40:
            break

    # Atom
    if not items:
        for el in root.iter("{http://www.w3.org/2005/Atom}entry"):
            items.append(_parse_atom_entry(el, src))
            if len(items) >= 40:
                break

    return items


def _parse_rss_item(el: ET.Element, src: dict[str, str]) -> dict[str, Any]:
    title = (el.findtext("title") or "").strip()
    link = (el.findtext("link") or "").strip()
    desc = (el.findtext("description") or "").strip()
    pub = (el.findtext("pubDate") or "").strip()
    # Strip HTML from description, basic but effective
    summary = _strip_html(desc)[:500]
    ts = _parse_date(pub)
    return _build_item(src, title, link, summary, pub, ts)


def _parse_atom_entry(el: ET.Element, src: dict[str, str]) -> dict[str, Any]:
    ns = "{http://www.w3.org/2005/Atom}"
    title = (el.findtext(f"{ns}title") or "").strip()
    link_el = el.find(f"{ns}link")
    link = (link_el.get("href") if link_el is not None else "").strip()
    summary_el = el.find(f"{ns}summary")
    content_el = el.find(f"{ns}content")
    desc = (summary_el.text if summary_el is not None and summary_el.text else
            (content_el.text if content_el is not None and content_el.text else "")).strip()
    pub = (el.findtext(f"{ns}updated") or el.findtext(f"{ns}published") or "").strip()
    summary = _strip_html(desc)[:500]
    ts = _parse_date(pub)
    return _build_item(src, title, link, summary, pub, ts)


def _build_item(src: dict[str, str], title: str, link: str, summary: str, pub: str, ts: float | None) -> dict[str, Any]:
    full_text = f"{title}\n{summary}"
    cves = sorted(set(m.upper() for m in CVE_RX.findall(full_text)))
    families = [f for f in MALWARE_FAMILIES if re.search(rf"\b{re.escape(f)}\b", full_text, re.I)]
    actors = [a for a in ACTOR_GROUPS if re.search(rf"\b{re.escape(a)}\b", full_text, re.I)]
    topics = _classify_topics(full_text)
    # If the item mentions a CVE but didn't hit Vulnerability patterns,
    # pull it in. CVE presence is a strong signal.
    if cves and "Vulnerability" not in topics:
        topics.append("Vulnerability")
    # If no specific topic matched but malware family did, keep Malware
    # even though it's the weakest tag.
    if families and "Malware" not in topics:
        topics.append("Malware")
    return {
        "id": _item_id(src["id"], link or title),
        "source_id": src["id"],
        "source_name": src["name"],
        "source_tier": src["tier"],
        "title": title,
        "link": link,
        "summary": summary,
        "published": pub,
        "published_ts": ts,
        "cves": cves,
        "malware_families": families,
        "actor_groups": actors,
        "topics": topics,
    }


def _fetch_kev() -> set[str]:
    """Fetch the CISA KEV catalog. Returns the set of CVE IDs."""
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read()
    data = json.loads(body.decode("utf-8"))
    cves: set[str] = set()
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if cve:
            cves.add(cve)
    return cves


# ── Helpers ───────────────────────────────────────────────────────────

_HTML_TAG_RX = re.compile(r"<[^>]+>")
_WS_RX = re.compile(r"\s+")


def _strip_html(s: str) -> str:
    no_tags = _HTML_TAG_RX.sub(" ", s)
    return _WS_RX.sub(" ", unescape(no_tags)).strip()


def _parse_date(s: str) -> float | None:
    if not s:
        return None
    try:
        dt = parsedate_to_datetime(s)
        return dt.timestamp() if dt else None
    except (TypeError, ValueError):
        pass
    # Atom ISO-8601
    try:
        from datetime import datetime
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _item_id(source_id: str, key: str) -> str:
    # Stable-ish id for de-dupe between refreshes. Not a hash, a cheap
    # projection so the UI can key on it.
    import hashlib
    return f"{source_id}-{hashlib.sha1(key.encode('utf-8', errors='replace')).hexdigest()[:12]}"
