"""ThreatDesk must stand alone: no SOC-in-a-Box imports, paths, port or Primus."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ["threatdesk", "api", ".claude", "web/src"]
BANNED = ["soc_in_a_box", "soc-in-a-box", "8443", "primus"]


def _files():
    for d in SCAN:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".md", ".ts", ".tsx", ".json", ".css"} and "node_modules" not in p.parts:
                yield p


def test_no_socbox_imports():
    hits = []
    for p in _files():
        text = p.read_text(encoding="utf-8", errors="ignore").lower()
        for b in BANNED:
            if b in text:
                hits.append(f"{p.relative_to(ROOT)}: {b}")
    assert hits == []


def test_runtime_defaults(tmp_path, monkeypatch):
    from threatdesk import runtime_settings
    monkeypatch.setattr(runtime_settings, "SETTINGS_PATH", tmp_path / "rt.json")
    s = runtime_settings.load()
    assert s["triage_model"] == "claude-opus-5-5"
    assert s["cyber_fallback_enabled"] is False
    assert s["use_subscription"] is False


def test_agent_env_keeps_api_key_by_default(tmp_path, monkeypatch):
    from threatdesk import runtime_settings, claude_runner
    monkeypatch.setattr(runtime_settings, "SETTINGS_PATH", tmp_path / "rt.json")
    assert "ANTHROPIC_API_KEY" not in claude_runner.agent_env()
    runtime_settings.save({"use_subscription": True})
    assert claude_runner.agent_env()["ANTHROPIC_API_KEY"] == ""
