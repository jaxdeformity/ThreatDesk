import json

import pytest

from threatdesk import inventory

HEADER = "id,category,subcategory,vendor,product,version,patched_through,environment,count,owner,criticality,internet_facing,match\n"


@pytest.fixture
def paths(tmp_path, monkeypatch):
    csv_p, json_p = tmp_path / "tech-stack.csv", tmp_path / "inventory.json"
    monkeypatch.setenv("THREATDESK_TECH_STACK_CSV", str(csv_p))
    monkeypatch.setenv("THREATDESK_INVENTORY", str(json_p))
    for k in ("THREATDESK_TECH_STACK", "SOC_ORG_TECH_STACK", "SOC_ORG_INVENTORY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(inventory, "UPLOAD_CSV", csv_p)
    return csv_p, json_p


def test_csv_parse(paths):
    csv_p, _ = paths
    csv_p.write_text(HEADER + "A-1,Network,VPN,Fortinet,FortiOS,7.2.5,2026-01-10,prod,40,netops,high,yes,Fortinet FortiOS;FortiGate\n", encoding="utf-8")
    [a] = inventory.load_assets()
    assert a["match"] == ["Fortinet FortiOS", "FortiGate"]
    assert a["internet_facing"] is True
    assert a["count"] == 40
    assert a["patched_through"] == "2026-01-10"
    assert a["subcategory"] == "VPN"


def test_bad_rows_skipped(paths):
    csv_p, _ = paths
    csv_p.write_text(HEADER + "A-1,Network,,Acme,,1.0,,,,,,no,\nA-2,Network,,Acme,Widget,1.0,,,,,medium,no,\n", encoding="utf-8")
    assets = inventory.load_assets()
    assert [a["product"] for a in assets] == ["Widget"]
    csv_status = next(s for s in inventory.sources_status() if s["name"] == "csv")
    assert csv_status["errors"] and "product" in csv_status["errors"][0]


def test_bom_header(paths):
    csv_p, _ = paths
    csv_p.write_bytes(("\ufeff" + HEADER + "A-1,App,,Citrix,NetScaler,14.1,,,,,,no,\n").encode("utf-8"))
    [a] = inventory.load_assets()
    assert a["id"] == "A-1"
    assert a["match"] == ["Citrix NetScaler"]


def test_precedence_csv_over_json(paths):
    csv_p, json_p = paths
    csv_p.write_text(HEADER + "C-1,App,,Microsoft,Exchange Server,2019,,,,csv-owner,high,no,\n", encoding="utf-8")
    json_p.write_text(json.dumps({"assets": [
        {"id": "J-1", "vendor": "Microsoft", "product": "Exchange Server", "version": "2019", "owner": "json-owner"},
        {"id": "J-2", "vendor": "Ivanti", "product": "Connect Secure", "version": "22.7"},
    ]}), encoding="utf-8")
    assets = inventory.load_assets()
    owners = {a["product"]: a["owner"] for a in assets}
    assert owners["Exchange Server"] == "csv-owner"
    assert len(assets) == 2


def test_env_terms_product_only(paths, monkeypatch):
    monkeypatch.setenv("THREATDESK_TECH_STACK", "Citrix, Fortinet FortiOS")
    assets = inventory.load_assets()
    assert [a["product"] for a in assets] == ["Citrix", "Fortinet FortiOS"]
    assert all(a["vendor"] == "" for a in assets)


def test_legacy_env_name(paths, monkeypatch):
    monkeypatch.setenv("SOC_ORG_TECH_STACK", "Citrix")
    assert [a["product"] for a in inventory.load_assets()] == ["Citrix"]


def test_save_csv_keeps_bak(paths):
    csv_p, _ = paths
    csv_p.write_text(HEADER + "A-1,App,,Old,Thing,1,,,,,,no,\n", encoding="utf-8")
    res = inventory.save_csv((HEADER + "B-1,App,,New,Thing,2,,,,,,no,\n").encode("utf-8"))
    assert res["count"] == 1
    assert "Old" in csv_p.with_suffix(".csv.bak").read_text(encoding="utf-8")
    assert inventory.load_assets()[0]["vendor"] == "New"


def test_save_csv_rejects_no_product_column(paths):
    with pytest.raises(ValueError):
        inventory.save_csv(b"id,vendor\n1,Acme\n")


def test_servicenow_slot_unconfigured(paths):
    sn = next(s for s in inventory.sources_status() if s["name"] == "servicenow")
    assert sn["configured"] is False


def test_same_product_two_rows_within_source_kept(paths):
    csv_p, _ = paths
    csv_p.write_text(HEADER + "A-1,App,,Acme,Widget,1.0,,prod,5,ops,high,no,\nA-2,App,,Acme,Widget,1.0,,dr,2,dr-team,low,no,\n", encoding="utf-8")
    assert [a["id"] for a in inventory.load_assets()] == ["A-1", "A-2"]


def test_bad_values_reported_row_kept(paths):
    csv_p, _ = paths
    csv_p.write_text(HEADER + "A-1,App,,Acme,Widget,1.0,,,abc,,urgent,maybe,\n", encoding="utf-8")
    [a] = inventory.load_assets()
    errs = next(s for s in inventory.sources_status() if s["name"] == "csv")["errors"]
    assert any("internet_facing" in e for e in errs)
    assert any("count" in e for e in errs)
    assert any("criticality" in e for e in errs)


def test_cp1252_csv_accepted(paths):
    data = ("vendor,product\nSchneider Électric,EcoStruxure\n").encode("cp1252")
    res = inventory.save_csv(data)
    assert res["count"] == 1
    assert inventory.load_assets()[0]["vendor"] == "Schneider Électric"


def test_upload_never_overwrites_pointed_sample(paths, tmp_path, monkeypatch):
    sample = tmp_path / "sample.csv"
    sample.write_text(HEADER + "S-1,App,,Old,Thing,1,,,,,,no,\n", encoding="utf-8")
    monkeypatch.setenv("THREATDESK_TECH_STACK_CSV", str(sample))
    monkeypatch.setattr(inventory, "UPLOAD_CSV", tmp_path / "config" / "tech-stack.csv")
    inventory.save_csv((HEADER + "N-1,App,,New,Thing,2,,,,,,no,\n").encode("utf-8"))
    assert "Old" in sample.read_text(encoding="utf-8")
    assert inventory.load_assets()[0]["vendor"] == "New"
