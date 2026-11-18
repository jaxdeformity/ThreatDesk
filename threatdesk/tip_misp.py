"""Export incidents / IOCs to MISP Event JSON.

MISP's ``Event`` JSON schema is documented at
https://www.misp-project.org/openapi/ and accepted by any MISP
instance via ``/events/add`` (or PyMISP's add_event). We don't need
to run MISP ourselves, we just emit the schema.

Two exports:

  - ``event_for_incident(packet)``  → one MISP Event object
  - ``bulk_export(packets, catalog)`` → {"response": [ Event, … ]}
    so a downstream `misp-restfull-client -F events.json` can load it

Attribute types we map to MISP's:

    ThreatDesk     →  MISP
    ipv4        →  ip-dst (or ip-src if disposition is attacker-source)
    ipv6        →  ip-dst (v6)
    domain      →  domain
    url         →  url
    email       →  email-src
    sha256      →  sha256
    sha1        →  sha1
    md5         →  md5
    filename    →  filename
    mutex       →  mutex
    registry_key → regkey

ATT&CK technique IDs come out as Galaxy Cluster references under
``Galaxy[]`` using the ``mitre-attack-pattern`` namespace.

This is explicitly a one-way export, not a full MISP implementation.
No attribute proposals, no sharing groups, no sightings, no object
templates beyond the minimum. Good enough to import into a real MISP
and correlate there; not good enough to be a MISP replacement.
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


def event_for_incident(packet: dict[str, Any]) -> dict[str, Any]:
    """Return a single MISP Event dict for this incident packet."""
    inc_id = packet.get("incident_id") or "unknown"
    summary = packet.get("summary") or inc_id
    info_line = f"ThreatDesk · {inc_id}: {summary}"

    sev = (packet.get("severity") or "medium").lower()
    # MISP threat_level_id: 1=high, 2=medium, 3=low, 4=undefined
    threat_level_id = {
        "critical": 1, "high": 1, "medium": 2, "low": 3,
    }.get(sev, 4)

    # MISP analysis: 0=initial, 1=ongoing, 2=completed
    stage = packet.get("picerl_stage")
    analysis = 2 if stage == "lessons_learned" else 1 if stage else 0

    # MISP distribution: 0=this org only (safe default for local tool)
    event: dict[str, Any] = {
        "info": info_line[:220],
        "uuid": _stable_uuid(inc_id),
        "date": _date_only(packet.get("created_at")),
        "timestamp": str(int(_epoch(packet.get("updated_at") or packet.get("created_at")))),
        "threat_level_id": str(threat_level_id),
        "analysis": str(analysis),
        "distribution": "0",
        "published": False,
        "Tag": _tags_for_packet(packet),
        "Galaxy": _galaxies_for_packet(packet),
        "Attribute": _attributes_for_packet(packet),
        "Object": [],
    }
    return event


def bulk_export(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a {"response": [Event, ...]} payload compatible with
    MISP's bulk-import and with PyMISP.add_event(…)."""
    return {
        "response": [event_for_incident(p) for p in packets],
        "meta": {
            "generator": "ThreatDesk TIP export",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(packets),
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────

def _attributes_for_packet(pkt: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn packet.iocs[] + promoted threat_triages[].iocs[] into MISP Attributes."""
    out: list[dict[str, Any]] = []

    # Direct packet IOCs
    for ioc in pkt.get("iocs") or []:
        attr = _ioc_to_attribute(ioc)
        if attr:
            out.append(attr)

    # Triage IOCs nested in threat_triages
    for tri in pkt.get("threat_triages") or []:
        for ioc in tri.get("iocs") or []:
            attr = _ioc_to_attribute(ioc)
            if attr:
                # Tag it so it's clear where it came from
                attr.setdefault("Tag", []).append({"name": f"source:triage={tri.get('id') or '?'}"})
                out.append(attr)

    # Evidence attachment hashes, useful for correlation across events
    for ev in pkt.get("evidence_attachments") or []:
        h = ev.get("sha256")
        if not h:
            continue
        out.append({
            "type": "sha256",
            "category": "Payload delivery",
            "to_ids": True,
            "distribution": "5",  # inherit event
            "value": h,
            "comment": f"evidence: {ev.get('original_name') or ev.get('name')}",
        })

    return out


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


def _galaxies_for_packet(pkt: dict[str, Any]) -> list[dict[str, Any]]:
    """ATT&CK techniques become a MITRE Galaxy cluster reference."""
    techs = pkt.get("attack_techniques") or []
    if not techs:
        return []
    clusters: list[dict[str, Any]] = []
    for t in techs:
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
        "description": "MITRE ATT&CK techniques observed in this incident",
        "namespace": "mitre-attack",
        "GalaxyCluster": clusters,
    }]


def _tags_for_packet(pkt: dict[str, Any]) -> list[dict[str, str]]:
    """Add TLP + origin + severity tags."""
    tags: list[dict[str, str]] = [
        {"name": "source:soc-box"},
        {"name": f"soc-box:stage={pkt.get('picerl_stage') or 'unknown'}"},
        {"name": f"soc-box:case-state={pkt.get('case_state') or 'active'}"},
        {"name": "tlp:amber"},  # defaulted, responder can relabel on import
    ]
    sev = pkt.get("severity")
    if sev:
        tags.append({"name": f"soc-box:severity={sev}"})
    return tags


def _stable_uuid(seed: str) -> str:
    """Deterministic UUIDv5-ish hash so re-exporting the same incident
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
