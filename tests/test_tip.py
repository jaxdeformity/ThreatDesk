import json

from threatdesk import tip_catalog, tip_misp


def _triage(root, tid, iocs, headline="H"):
    d = root / tid
    d.mkdir(parents=True)
    (d / "input.json").write_text(json.dumps({"triage_id": tid, "created_at": "2026-11-18T10:00:00+00:00"}), encoding="utf-8")
    (d / "result.json").write_text(json.dumps({"headline": headline, "iocs": iocs}), encoding="utf-8")


def test_catalog_from_triages(tmp_path):
    _triage(tmp_path, "TRG-1", [{"type": "domain", "value": "evil.example.com", "disposition": "c2"}])
    _triage(tmp_path, "TRG-2", [{"type": "domain", "value": "EVIL.example.com"}, {"type": "ipv4", "value": "192.0.2.10"}])
    cat = tip_catalog.build_catalog(tmp_path)
    dom = next(r for r in cat if r["type"] == "domain")
    assert dom["observation_count"] == 2
    assert dom["related_triages"] == ["TRG-1", "TRG-2"]
    assert "related_incidents" not in dom
    assert len(cat) == 2


def test_catalog_missing_dir(tmp_path):
    assert tip_catalog.build_catalog(tmp_path / "nope") == []


def test_misp_event_for_triage():
    detail = {
        "triage_id": "TRG-9",
        "input": {"created_at": "2026-11-18T10:00:00+00:00"},
        "result": {
            "headline": "AgentTesla wave", "severity": "high",
            "iocs": [{"type": "sha256", "value": "a" * 64}, {"type": "domain", "value": "bad.example.net"}],
            "ttps": [{"technique_id": "T1566", "name": "Phishing"}],
        },
    }
    ev = tip_misp.event_for_triage(detail)
    assert [a["type"] for a in ev["Attribute"]] == ["sha256", "domain"]
    assert ev["threat_level_id"] == "1"
    assert ev["info"].startswith("ThreatDesk · TRG-9")
    assert ev["Galaxy"][0]["GalaxyCluster"][0]["value"] == "Phishing - T1566"
    assert {"name": "source:threatdesk"} in ev["Tag"]
    assert ev["uuid"] == tip_misp.event_for_triage(detail)["uuid"]


def test_bulk_export_triages():
    out = tip_misp.bulk_export([{"triage_id": "A", "result": {"iocs": []}}, {"triage_id": "B", "result": None}])
    assert out["meta"]["event_count"] == 2


def test_misp_matches_catalog_normalisation():
    detail = {"triage_id": "TRG-7", "result": {"iocs": [
        {"type": "IP", "value": "192.0.2.5"}, {"type": "hostname", "value": "x.example.org"},
        {"type": "sha-256", "value": "b" * 64}, {"type": "url", "value": 12345}, "198.51.100.7",
    ], "key_findings": [{"statement": "Mass exploitation observed", "disposition": "malicious"}]}}
    ev = tip_misp.event_for_triage(detail)
    vals = {a["value"] for a in ev["Attribute"]}
    assert {"192.0.2.5", "x.example.org", "b" * 64, "198.51.100.7"} <= vals
    assert any(a["type"] == "text" and "Mass exploitation" in a["value"] for a in ev["Attribute"])
