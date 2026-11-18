"""Org technology inventory: the one list of what the enterprise runs.

Vulns matches known-exploited CVEs against it; the triage agent reads it
(via ``GET /api/environment``) when "use environment" is ticked.

Sources, highest precedence first. On a vendor+product+version collision
the earlier source wins:

  1. ``csv``  - the tech-stack doc: an uploaded ``config/tech-stack.csv``
                if present, else ``THREATDESK_TECH_STACK_CSV`` (template in
                ``config/tech-stack.template.csv``)
  2. ``json`` - an inventory JSON ``{"assets": [...]}``, ``THREATDESK_INVENTORY``
                (``SOC_ORG_INVENTORY`` accepted)
  3. ``env``  - a comma list of product names, ``THREATDESK_TECH_STACK``
                (``SOC_ORG_TECH_STACK`` accepted). Product-only matching.
  4. ``servicenow`` - slot only. A future adapter implements
                ``load() -> list[asset]`` and ``status()``; see docs/SERVICENOW.md.

Asset shape (what ``vulns`` consumes): id, category, subcategory, vendor,
product, version, patched_through, environment, count, owner,
criticality (crown_jewel|high|medium|low), internet_facing, match[].
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = "config/tech-stack.csv"
# Where Settings uploads land. Never the THREATDESK_TECH_STACK_CSV target
# (that may be a tracked sample); an uploaded file takes precedence over it.
UPLOAD_CSV = REPO_ROOT / DEFAULT_CSV

CSV_COLUMNS = ["id", "category", "subcategory", "vendor", "product", "version", "patched_through",
               "environment", "count", "owner", "criticality", "internet_facing", "match"]
CRITICALITIES = ("crown_jewel", "high", "medium", "low")
_TRUE = {"yes", "y", "true", "1", "x"}
_FALSE = {"no", "n", "false", "0", ""}

_cache: dict[str, Any] = {"key": None, "assets": [], "errors": {}}


def _resolve(raw: str) -> Path:
    p = Path(raw)
    return p if p.is_absolute() else REPO_ROOT / p


def csv_path() -> Path:
    """The active tech-stack CSV: an uploaded one wins, else the env path."""
    if UPLOAD_CSV.exists():
        return UPLOAD_CSV
    return _resolve(os.environ.get("THREATDESK_TECH_STACK_CSV", "").strip() or DEFAULT_CSV)


def json_path() -> Path | None:
    raw = (os.environ.get("THREATDESK_INVENTORY") or os.environ.get("SOC_ORG_INVENTORY") or "").strip()
    return _resolve(raw) if raw else None


def env_terms() -> list[str]:
    raw = os.environ.get("THREATDESK_TECH_STACK") or os.environ.get("SOC_ORG_TECH_STACK") or ""
    return [t.strip() for t in re.split(r"[,;\n]", raw) if t.strip()][:100]


def _mtime(p: Path | None) -> float | None:
    try:
        return p.stat().st_mtime if p else None
    except OSError:
        return None


def cache_key() -> tuple:
    c, j = csv_path(), json_path()
    return (str(c), _mtime(c), str(j), _mtime(j), tuple(env_terms()))


def _norm_asset(a: dict[str, Any], errors: list[str] | None = None, where: str = "") -> dict[str, Any]:
    vendor = str(a.get("vendor") or "").strip()
    product = str(a.get("product") or "").strip()
    match = a.get("match")
    if isinstance(match, str):
        match = [m.strip() for m in match.split(";") if m.strip()]
    if not match:
        match = [f"{vendor} {product}".strip()]
    count = a.get("count")
    errs = errors if errors is not None else []
    try:
        count = int(count) if count not in (None, "") else None
    except (TypeError, ValueError):
        errs.append(f"{where}bad count {count!r} (ignored)")
        count = None
    raw_crit = str(a.get("criticality") or "").strip()
    crit = raw_crit.lower().replace(" ", "_").replace("-", "_") or "medium"
    if crit not in CRITICALITIES:
        errs.append(f"{where}bad criticality {raw_crit!r} (used medium)")
    ife = a.get("internet_facing")
    if not isinstance(ife, bool):
        raw = str(ife or "").strip().lower()
        if raw and raw not in _TRUE | _FALSE:
            errs.append(f"{where}bad internet_facing {ife!r} (used no)")
        ife = raw in _TRUE
    return {
        "id": str(a.get("id") or "").strip(),
        "category": str(a.get("category") or "").strip(),
        "subcategory": str(a.get("subcategory") or "").strip(),
        "vendor": vendor,
        "product": product,
        "version": str(a.get("version") or "").strip(),
        "patched_through": str(a.get("patched_through") or "").strip() or None,
        "environment": str(a.get("environment") or "").strip(),
        "count": count,
        "owner": str(a.get("owner") or "").strip(),
        "criticality": crit if crit in CRITICALITIES else "medium",
        "internet_facing": ife,
        "match": match,
    }


def decode_csv(data: bytes) -> str:
    """UTF-8 (with or without BOM), falling back to Windows-1252, which is
    what Excel's default "CSV (Comma delimited)" writes."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def parse_csv(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse tech-stack CSV text. Returns (assets, row errors)."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    fields = [f.strip().lower() for f in (reader.fieldnames or [])]
    if "product" not in fields:
        raise ValueError("tech-stack CSV needs a 'product' column (see config/tech-stack.template.csv)")
    assets, errors = [], []
    for n, row in enumerate(reader, start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        if not any(row.values()):
            continue
        if not row.get("product"):
            errors.append(f"row {n}: missing product")
            continue
        a = _norm_asset(row, errors, f"row {n}: ")
        a["id"] = a["id"] or f"CSV-{n:04d}"
        assets.append(a)
    return assets, errors


def _load_csv() -> tuple[list[dict[str, Any]], list[str]]:
    p = csv_path()
    if not p.exists():
        return [], []
    try:
        return parse_csv(decode_csv(p.read_bytes()))
    except (OSError, ValueError, csv.Error) as e:
        log.warning("inventory: %s unreadable: %s", p, e)
        return [], [str(e)]


def _load_json() -> tuple[list[dict[str, Any]], list[str]]:
    p = json_path()
    if not p or not p.exists():
        return [], []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        log.warning("inventory: %s unreadable: %s", p, e)
        return [], [str(e)]
    out, errors = [], []
    for i, a in enumerate(data.get("assets") or [], 1):
        if isinstance(a, dict) and a.get("product"):
            na = _norm_asset(a)
            na["id"] = na["id"] or f"JSON-{i:04d}"
            out.append(na)
        else:
            errors.append(f"asset {i}: missing product")
    return out, errors


def _load_env() -> list[dict[str, Any]]:
    return [_norm_asset({"id": f"ENV-{i:03d}", "category": "Listed in .env", "product": t, "match": [t]})
            for i, t in enumerate(env_terms(), 1)]


def load_assets() -> list[dict[str, Any]]:
    """Merged inventory, memoised on file mtimes + env list."""
    key = cache_key()
    if _cache["key"] == key:
        return _cache["assets"]
    c_assets, c_err = _load_csv()
    j_assets, j_err = _load_json()
    # De-dup only ACROSS sources (CSV > JSON > env list): the same product
    # listed twice in one source (prod + DR, different owners) is kept.
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source in (c_assets, j_assets, _load_env()):
        keys = set()
        for a in source:
            k = (a["vendor"].lower(), a["product"].lower(), a["version"].lower())
            if k in seen:
                continue
            keys.add(k)
            merged.append(a)
        seen |= keys
    _cache.update(key=key, assets=merged, errors={"csv": c_err, "json": j_err},
                  counts={"csv": len(c_assets), "json": len(j_assets), "env": len(env_terms())})
    return merged


def _display(p: Path | None) -> str | None:
    """Repo-relative path for display (no user directory in the UI)."""
    if not p:
        return None
    try:
        return p.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(p)


def sources_status() -> list[dict[str, Any]]:
    load_assets()
    errs, counts = _cache.get("errors", {}), _cache.get("counts", {})
    c, j = csv_path(), json_path()
    return [
        {"name": "csv", "label": "Tech-stack doc (CSV)", "configured": c.exists(), "path": _display(c),
         "count": counts.get("csv", 0), "errors": errs.get("csv", [])},
        {"name": "json", "label": "Inventory JSON", "configured": bool(j and j.exists()), "path": _display(j),
         "count": counts.get("json", 0), "errors": errs.get("json", [])},
        {"name": "env", "label": "Product list (.env)", "configured": bool(env_terms()), "path": None,
         "count": counts.get("env", 0), "errors": []},
        {"name": "servicenow", "label": "ServiceNow CMDB", "configured": False, "path": None, "count": 0,
         "errors": [], "note": "Not configured. Adapter slot: see docs/SERVICENOW.md."},
    ]


def save_csv(data: bytes) -> dict[str, Any]:
    """Store an uploaded tech-stack CSV at config/tech-stack.csv (previous
    upload kept as .bak). Validates first; never writes to the
    THREATDESK_TECH_STACK_CSV path, which may be a tracked sample."""
    text = decode_csv(data)
    try:
        assets, errors = parse_csv(text)  # raises ValueError on a bad header
    except csv.Error as e:
        raise ValueError(f"not a readable CSV: {e}") from e
    p = UPLOAD_CSV
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        p.with_suffix(".csv.bak").write_bytes(p.read_bytes())
    tmp = p.with_suffix(".csv.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)
    _cache["key"] = None
    return {"ok": True, "count": len(assets), "errors": errors, "path": str(p)}
