"""Threat-Intelligence Platform. IOC catalog aggregator.

Walks the triage corpus on demand and produces a
normalized, de-duplicated list of every indicator of compromise ever
observed. No database; computed fresh on each request. The triages
directory is the source of truth: delete a triage and its IOCs
disappear from the catalog.

Shape of each record the API returns:

    {
      "type": "ipv4",
      "value": "10.0.2.15",
      "normalized_value": "10.0.2.15",    # lowercased / defanged for matching
      "observations": [
          {
              "source": "triage",
              "id": "TRG-2026-...",
              "summary": "GuLoader for AgentTesla",
              "ioc_id": "I7",
              "disposition": "attacker",
              "notes": "FTP exfil destination",
              "seen_at": "2026-04-23T18:41:00Z"
          },
          ...
      ],
      "observation_count": 3,
      "first_seen": "2026-02-12T09:41:00Z",
      "last_seen": "2026-04-23T18:41:00Z",
      "dispositions": ["c2", "attacker"],
      "related_triages":   ["TRG-…"]
    }

IOC types observed in-the-wild in triage results: ipv4, ipv6,
domain, url, email, sha256, sha1, md5, filename, mutex, registry_key.
The catalog doesn't enforce a closed set, whatever the agents wrote
shows up here.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


log = logging.getLogger(__name__)


# ── Shape ─────────────────────────────────────────────────────────────

@dataclass
class Observation:
    source: str                 # "triage"
    id: str                     # INC-… or TRG-…
    summary: str                # triage.headline
    ioc_id: str | None = None   # id the triage gave the IOC, if any
    disposition: str | None = None
    notes: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    seen_at: str | None = None


# ── Normalization ─────────────────────────────────────────────────────

# Defang decoder, agents are asked to defang IOCs in narrative but
# often the iocs[] entries are fanged; still, some sources push
# defanged values. Collapse both shapes to the fanged original so the
# catalog merges them.
def _normalize_value(t: str, v: str) -> str:
    s = (v or "").strip()
    # Strip surrounding brackets / quotes
    s = s.strip('"\'`')
    # Defang to fanged: hxxp → http, [.] → .
    s = s.replace("hxxp://", "http://").replace("hxxps://", "https://")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]", ":").replace("(:)", ":")
    s = s.replace("[@]", "@").replace("(@)", "@")
    # Hashes + domains + emails + urls: lowercase
    tlow = (t or "").lower()
    if tlow in {"sha256", "sha1", "md5", "domain", "email", "url", "filename"}:
        s = s.lower()
    return s


def _canonical_type(t: str) -> str:
    """Collapse type-name variants to a canonical form."""
    s = (t or "").lower().strip()
    aliases = {
        "ip": "ipv4",
        "ipaddr": "ipv4",
        "ipv4addr": "ipv4",
        "ip-dst": "ipv4",
        "ip-src": "ipv4",
        "md5sum": "md5",
        "sha-256": "sha256",
        "sha-1": "sha1",
        "email-addr": "email",
        "hostname": "domain",
        "host": "domain",
        "uri": "url",
        "link": "url",
    }
    return aliases.get(s, s)


# ── Catalog build ─────────────────────────────────────────────────────

def build_catalog(triages_dir: Path) -> list[dict[str, Any]]:
    """Return the full IOC catalog, built from every triage result.json.
    Call from an endpoint on demand; cheap enough at triage scale."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    if triages_dir.exists():
        for t_dir in triages_dir.iterdir():
            if not t_dir.is_dir():
                continue
            inp_path = t_dir / "input.json"
            res_path = t_dir / "result.json"
            if not res_path.exists():
                continue
            try:
                res = json.loads(res_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            try:
                inp = json.loads(inp_path.read_text(encoding="utf-8")) if inp_path.exists() else {}
            except (OSError, json.JSONDecodeError):
                inp = {}
            tri_id = t_dir.name
            tri_summary = res.get("headline") or inp.get("question") or inp.get("input_ref") or tri_id
            ts = inp.get("created_at")
            for ioc in res.get("iocs") or []:
                ioc_d = _coerce_ioc(ioc)
                if not ioc_d:
                    continue
                _merge_observation(
                    merged, ioc_d,
                    obs=Observation(
                        source="triage",
                        id=tri_id,
                        summary=tri_summary,
                        ioc_id=None,
                        disposition=ioc_d.get("disposition"),
                        notes=None,
                        evidence_refs=[],
                        seen_at=ts,
                    ),
                )

    # Roll up observations into the final record shape.
    out: list[dict[str, Any]] = []
    for (t, v), rec in merged.items():
        observations: list[Observation] = rec["obs"]
        sorted_obs = sorted(observations, key=lambda o: o.seen_at or "")
        first_seen = sorted_obs[0].seen_at if sorted_obs else None
        last_seen = sorted_obs[-1].seen_at if sorted_obs else None
        dispositions = sorted({o.disposition for o in observations if o.disposition})
        related_triages = sorted({o.id for o in observations if o.source == "triage"})
        out.append({
            "type": t,
            "value": rec["original_value"],
            "normalized_value": v,
            "observations": [_obs_to_dict(o) for o in sorted_obs],
            "observation_count": len(observations),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "dispositions": list(dispositions),
            "related_triages": related_triages,
        })

    # Most-observed first, then newest-last-seen.
    out.sort(key=lambda r: (r["observation_count"], r["last_seen"] or ""), reverse=True)
    return out


def _merge_observation(
    merged: dict[tuple[str, str], dict[str, Any]],
    ioc: Any,
    *,
    obs: Observation,
) -> None:
    # Agents occasionally emit bare strings ("10.0.2.15") or malformed
    # entries instead of the full {type, value, ...} dict. Don't crash
    # the whole catalog for one bad record, coerce, or skip.
    ioc_dict = _coerce_ioc(ioc)
    if not ioc_dict:
        return
    t = _canonical_type(ioc_dict.get("type", ""))
    v_original = (ioc_dict.get("value") or "").strip()
    v_normalized = _normalize_value(t, v_original)
    if not v_normalized or not t:
        return
    key = (t, v_normalized)
    if key not in merged:
        merged[key] = {"original_value": v_original, "obs": []}
    merged[key]["obs"].append(obs)


# Type-shape guesses used when an ioc comes in as a bare string. Keep
# the regex list short, we'd rather drop to "unknown" than mis-label.
_IPV4_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RX = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_SHA256_RX = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RX = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RX = re.compile(r"^[a-fA-F0-9]{32}$")
_EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_URL_RX = re.compile(r"^https?://", re.I)
_DOMAIN_RX = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", re.I)


def _guess_type(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if _URL_RX.match(v):    return "url"
    if _EMAIL_RX.match(v):  return "email"
    if _SHA256_RX.match(v): return "sha256"
    if _SHA1_RX.match(v):   return "sha1"
    if _MD5_RX.match(v):    return "md5"
    if _IPV4_RX.match(v):   return "ipv4"
    if _IPV6_RX.match(v):   return "ipv6"
    if _DOMAIN_RX.match(v): return "domain"
    return "unknown"


def _coerce_ioc(ioc: Any) -> dict[str, Any] | None:
    """Turn whatever the agent wrote into a {type, value, ...} dict.
    Return None for uncoercible junk so the caller can skip it."""
    if isinstance(ioc, dict):
        return ioc
    if isinstance(ioc, str):
        v = ioc.strip()
        if not v:
            return None
        return {"type": _guess_type(v), "value": v}
    # Anything else (list, int, None) is malformed
    return None


def _obs_to_dict(o: Observation) -> dict[str, Any]:
    return {
        "source": o.source,
        "id": o.id,
        "summary": o.summary,
        "ioc_id": o.ioc_id,
        "disposition": o.disposition,
        "notes": o.notes,
        "evidence_refs": o.evidence_refs,
        "seen_at": o.seen_at,
    }


def find(
    catalog: list[dict[str, Any]],
    *,
    ioc_type: str | None = None,
    value: str | None = None,
) -> dict[str, Any] | None:
    """Look up a single IOC by (type, normalized value)."""
    if not ioc_type or not value:
        return None
    t = _canonical_type(ioc_type)
    v = _normalize_value(t, value)
    for rec in catalog:
        if rec["type"] == t and rec["normalized_value"] == v:
            return rec
    return None


# ── Stats ─────────────────────────────────────────────────────────────

def summarize(catalog: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by type + total observation count."""
    by_type: dict[str, int] = {}
    total_observations = 0
    for r in catalog:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        total_observations += r["observation_count"]
    return {
        "total_iocs": len(catalog),
        "total_observations": total_observations,
        "by_type": by_type,
    }
