"""Export triage IOCs to MISP Event JSON.

  - ``event_for_triage(detail)``  -> one MISP Event per triage
  - ``bulk_export(details)``      -> {"response": [Event, ...]}

``detail`` is what ``triage_orchestrator.read_triage`` returns
({triage_id, input, status, result, ...}). IOC type mapping:

    ipv4/ipv6 -> ip-dst (ip-src when disposition says attacker/source)
    domain -> domain, url -> url, email -> email-src,
    sha256/sha1/md5 -> same, filename, mutex, registry_key -> regkey

ATT&CK techniques from ``result.ttps`` come out as Galaxy Cluster
references in the ``mitre-attack-pattern`` namespace.

One-way export only: no proposals, sharing groups or sightings. Good
enough to import into a real MISP and correlate there.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


MISP_TYPE_MAP: dict[str, str] = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "email": "email-src",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "filename": "filename",
    "mutex": "mutex",
    "registry_key": "regkey",
}

MISP_CATEGORY_MAP: dict[str, str] = {
    "ip-dst": "Network activity",
    "ip-src": "Network activity",
    "domain": "Network activity",
    "url": "Network activity",
    "email-src": "Payload delivery",
    "sha256": "Payload delivery",
    "sha1": "Payload delivery",
    "md5": "Payload delivery",
    "filename": "Payload delivery",
    "mutex": "Artifacts dropped",
    "regkey": "Persistence mechanism",
}


def event_for_triage(detail: dict[str, Any]) -> dict[str, Any]:
    """Return a single MISP Event dict for one triage."""
    tid = detail.get("triage_id") or "unknown"
    res = detail.get("result") or {}
    inp = detail.get("input") or {}
    created = inp.get("created_at")
    headline = res.get("headline") or inp.get("input_ref") or tid
    sev = str(res.get("severity") or "").lower()
    # MISP threat_level_id: 1=high, 2=medium, 3=low, 4=undefined
    threat_level_id = {"critical": 1, "high": 1, "medium": 2, "low": 3}.get(sev, 4)
    status = (detail.get("status") or {}).get("status")
    tags = [{"name": "source:threatdesk"}, {"name": "tlp:amber"}]
    if sev:
        tags.append({"name": f"threatdesk:severity={sev}"})
    if res.get("exploitation_status"):
        tags.append({"name": f"threatdesk:exploitation={res['exploitation_status']}"})
    return {
        "info": f"ThreatDesk · {tid}: {headline}"[:220],
        "uuid": _stable_uuid(tid),
        "date": _date_only(created),
        "timestamp": str(int(_epoch(created))),
        "threat_level_id": str(threat_level_id),
        # MISP analysis: 0=initial, 1=ongoing, 2=completed
        "analysis": "2" if status == "done" else "1",
        # MISP distribution: 0=this org only (safe default for a local tool)
        "distribution": "0",
        "published": False,
        "Tag": tags,
        "Galaxy": _galaxies(res.get("ttps") or []),
        "Attribute": [a for a in (_ioc_to_attribute(i) for i in res.get("iocs") or [] if isinstance(i, dict)) if a],
        "Object": [],
    }


def bulk_export(details: list[dict[str, Any]]) -> dict[str, Any]:
    """{"response": [Event, ...]}, compatible with MISP bulk import / PyMISP."""
    return {
        "response": [event_for_triage(d) for d in details],
        "meta": {
            "generator": "ThreatDesk TIP export",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(details),
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────

def _ioc_to_attribute(ioc: dict[str, Any]) -> dict[str, Any] | None:
    t = (ioc.get("type") or "").lower()
    v = (ioc.get("value") or "").strip()
    if not t or not v:
        return None
    misp_t = MISP_TYPE_MAP.get(t)
    if not misp_t:
        return None
    # Disposition hints src-vs-dst for IP types
    if t in ("ipv4", "ipv6"):
        dispo = (ioc.get("disposition") or "").lower()
        if dispo in ("attacker", "attacker-source", "source"):
            misp_t = "ip-src"
    attr: dict[str, Any] = {
        "type": misp_t,
        "category": MISP_CATEGORY_MAP.get(misp_t, "Network activity"),
        "to_ids": True,
        "distribution": "5",  # inherit from event
        "value": v,
    }
    notes = ioc.get("notes") or ioc.get("disposition")
    if notes:
        attr["comment"] = str(notes)[:500]
    return attr


def _galaxies(techs: list[Any]) -> list[dict[str, Any]]:
    """ATT&CK techniques become a MITRE Galaxy cluster reference."""
    if not techs:
        return []
    clusters: list[dict[str, Any]] = []
    for t in techs:
        if not isinstance(t, dict):
            continue
        tid = t.get("technique_id") or t.get("id")
        if not tid:
            continue
        name = t.get("name") or tid
        clusters.append({
            "uuid": _stable_uuid(f"attack-{tid}"),
            "value": f"{name} - {tid}",
            "type": "mitre-attack-pattern",
            "tag_name": f"misp-galaxy:mitre-attack-pattern=\"{name} - {tid}\"",
        })
    if not clusters:
        return []
    return [{
        "name": "Attack Pattern",
        "type": "mitre-attack-pattern",
        "description": "MITRE ATT&CK techniques cited by this triage",
        "namespace": "mitre-attack",
        "GalaxyCluster": clusters,
    }]


def _stable_uuid(seed: str) -> str:
    """Deterministic UUIDv5-ish hash so re-exporting the same triage
    produces the same MISP event UUID (makes de-dupe on import trivial)."""
    h = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    # Shape as 8-4-4-4-12
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _date_only(ts: str | None) -> str:
    if not ts:
        return datetime.now(timezone.utc).date().isoformat()
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.date().isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).date().isoformat()


def _epoch(ts: str | None) -> float:
    if not ts:
        return datetime.now(timezone.utc).timestamp()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).timestamp()
