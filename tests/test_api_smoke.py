import io
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATDESK_TECH_STACK_CSV", str(tmp_path / "ts.csv"))
    for k in ("THREATDESK_TECH_STACK", "THREATDESK_INVENTORY", "SOC_ORG_TECH_STACK", "SOC_ORG_INVENTORY"):
        monkeypatch.delenv(k, raising=False)
    from api import main
    from threatdesk import runtime_settings, triage_orchestrator, vulns
    monkeypatch.setattr(runtime_settings, "SETTINGS_PATH", tmp_path / "rt.json")
    monkeypatch.setattr(triage_orchestrator, "TRIAGES_DIR", tmp_path / "triages")
    monkeypatch.setattr(main, "TRIAGES_DIR_PATH", tmp_path / "triages")
    monkeypatch.setattr(main, "ENV_CONFIG_PATH", tmp_path / "environment.json")
    monkeypatch.setattr(vulns, "TRACKING_PATH", tmp_path / "t.json")
    monkeypatch.setattr(vulns, "kev_catalog", lambda: [])
    monkeypatch.setattr(vulns, "vuln_news_items", lambda *a, **k: [])
    return TestClient(main.app)


def test_health(client):
    assert client.get("/api/health").json()["product"] == "ThreatDesk"


def test_vulns_empty_inventory(client):
    r = client.get("/api/vulns/inventory")
    assert r.status_code == 200
    assert r.json()["assets"] == []
    assert client.get("/api/vulns?scope=org").status_code == 200


def test_environment_fallback_example(client):
    body = client.get("/api/environment").json()
    assert body["source"] == "example"
    assert body["inventory"] == []
    assert "assets" not in body["environment"]


def test_environment_roundtrip(client):
    assert client.post("/api/environment", json={"environment": {"org": {"name": "Example Corp"}}}).json()["ok"]
    assert client.get("/api/environment").json()["environment"]["org"]["name"] == "Example Corp"


def test_feed_upstream_down_returns_200(client, monkeypatch):
    from threatdesk import threat_feed

    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(threat_feed.urllib.request, "urlopen", boom)
    r = client.get("/api/threats/feed?force=1")
    assert r.status_code == 200
    assert isinstance(r.json().get("items", []), list)


def test_triage_create_hashes_attachment(client, monkeypatch):
    from threatdesk import triage_orchestrator

    async def noop(tid):
        return None

    monkeypatch.setattr(triage_orchestrator, "_run_triage", noop)
    r = client.post("/api/triage", data={"input_type": "file", "question": "?"},
                    files={"files": ("../../evil.txt", io.BytesIO(b"hello"), "text/plain")})
    assert r.status_code == 200, r.text
    tid = r.json()["triage_id"]
    inp = client.get(f"/api/triage/{tid}").json()["input"]
    assert inp["attached_files"] == ["evil.txt"]
    assert inp["attachment_sha256"]["evil.txt"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert "model_preference" not in inp
    assert any(t["triage_id"] == tid for t in client.get("/api/triages").json()["triages"])


def test_triage_bad_input_type(client):
    assert client.post("/api/triage", data={"input_type": "primus"}).status_code == 400


def test_tip_iocs_and_misp(client, tmp_path):
    d = tmp_path / "triages" / "TRG-X"
    d.mkdir(parents=True)
    (d / "input.json").write_text(json.dumps({"triage_id": "TRG-X", "created_at": "2026-11-18T00:00:00+00:00"}), encoding="utf-8")
    (d / "status.json").write_text(json.dumps({"status": "done"}), encoding="utf-8")
    (d / "result.json").write_text(json.dumps({"headline": "h", "iocs": [{"type": "domain", "value": "bad.example.com"}]}), encoding="utf-8")
    (d / "events.jsonl").touch()
    body = client.get("/api/tip/iocs").json()
    assert body["total"] == 1
    ev = client.get("/api/tip/misp-export?triage_id=TRG-X").json()
    assert ev["Attribute"][0]["value"] == "bad.example.com"
    assert client.get("/api/tip/misp-export").json()["meta"]["event_count"] == 1
    assert client.get("/api/tip/misp-export?triage_id=nope").status_code == 404


def test_inventory_sources_lists_servicenow_unconfigured(client):
    srcs = {s["name"]: s for s in client.get("/api/inventory/sources").json()["sources"]}
    assert srcs["servicenow"]["configured"] is False


def test_inventory_csv_upload(client):
    csv = b"vendor,product,version\nFortinet,FortiOS,7.2\n"
    r = client.put("/api/inventory/csv", files={"file": ("ts.csv", io.BytesIO(csv), "text/csv")})
    assert r.status_code == 200 and r.json()["count"] == 1
    assert client.get("/api/environment").json()["inventory"][0]["product"] == "FortiOS"
    bad = client.put("/api/inventory/csv", files={"file": ("x.csv", io.BytesIO(b"a,b\n1,2\n"), "text/csv")})
    assert bad.status_code == 400


def test_runtime_settings_roundtrip(client):
    s = client.get("/api/settings/runtime").json()["settings"]
    assert s["triage_model"] == "claude-opus-5-5"
    r = client.post("/api/settings/runtime", json={"use_subscription": True}).json()
    assert r["settings"]["use_subscription"] is True


def test_settings_endpoints_ok(client):
    for path in ("/api/ai/config", "/api/settings/agents", "/api/settings/service-keys", "/api/tip/enrichers"):
        assert client.get(path).status_code == 200, path


def test_no_promote_or_llm_routes(client):
    paths = {r.path for r in client.app.routes}
    assert not any("promote" in p or p.startswith("/api/llm") or "incident" in p for p in paths)
