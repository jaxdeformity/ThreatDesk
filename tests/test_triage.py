import asyncio
import json
from pathlib import Path

import pytest

from threatdesk import triage_orchestrator as T


@pytest.fixture
def tdir(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "TRIAGES_DIR", tmp_path / "triages")
    from threatdesk import runtime_settings
    monkeypatch.setattr(runtime_settings, "SETTINGS_PATH", tmp_path / "rt.json")
    from threatdesk import ai_config
    monkeypatch.setattr(ai_config, "CONFIG_PATH", tmp_path / "ai_config.json")
    return tmp_path / "triages"


class FakeRunner:
    calls: list[dict] = []

    def available(self):
        return True

    async def run_turn(self, **kw):
        FakeRunner.calls.append(kw)
        d = Path(kw["add_dirs"][0])
        yield {"kind": "text", "text": "researching"}
        (d / "report.md").write_text("# Report", encoding="utf-8")
        (d / "result.json").write_text(json.dumps({"headline": "X", "actor_group": {"name": "APT0"}}), encoding="utf-8")
        yield {"kind": "tool_call", "tool_name": "Write"}
        yield {"kind": "session_complete"}


async def test_lifecycle_fake_runner(tdir, monkeypatch):
    monkeypatch.setattr(T, "ClaudeRunner", FakeRunner)
    res = await T.create_triage(input_type="threat_name", input_ref="OtterCookie", input_text=None,
                                question="does it matter?", use_environment=True)
    tid = res["triage_id"]
    for _ in range(100):
        await asyncio.sleep(0.01)
        if T.read_triage(tid)["status"]["status"] in ("done", "error"):
            break
    detail = T.read_triage(tid)
    assert detail["status"]["status"] == "done"
    assert detail["result"]["actor_group"] == "APT0"  # sanitized to a scalar
    events = (tdir / tid / "events.jsonl").read_text(encoding="utf-8").splitlines()
    kinds = [json.loads(e)["kind"] for e in events]
    assert kinds[0] == "triage_status" and "session_complete" in kinds and kinds[-1] == "triage_status"
    kw = FakeRunner.calls[-1]
    assert kw["model"] == "claude-opus-5-5"
    assert "ThreatDesk" in kw["system_prompt_append"]
    assert "8444" in kw["user_prompt"] or "THREATDESK_PORT" in kw["user_prompt"]


async def test_fallback_disabled_by_default(tdir, monkeypatch):
    seen = {}

    async def fake_fallback(runner, *, model, fallback_model, **kw):
        seen["fallback_model"] = fallback_model
        yield {"kind": "session_complete"}

    from threatdesk import model_policy
    monkeypatch.setattr(model_policy, "run_turn_with_fallback", fake_fallback)
    monkeypatch.setattr(T, "ClaudeRunner", FakeRunner)
    res = await T.create_triage(input_type="threat_name", input_ref="x", input_text=None, question="")
    for _ in range(50):
        await asyncio.sleep(0.01)
        if "fallback_model" in seen:
            break
    assert seen["fallback_model"] is None


def test_safe_attachment_name():
    assert T.safe_attachment_name("../../x.exe") == "x.exe"
    assert T.safe_attachment_name("..\..\evil.dll") == "evil.dll"
    assert T.safe_attachment_name("") == "upload.bin"
    assert T.safe_attachment_name("..") == "upload.bin"


def test_no_primus_symbols():
    src = Path(T.__file__).read_text(encoding="utf-8").lower()
    assert "primus" not in src
    assert "promote" not in src


@pytest.mark.parametrize("bad", ["..", "C:\Windows", "../x", "TRG-2026-11-18-000000-zzzzzz", "foo"])
def test_triage_id_rejected(tdir, bad):
    tdir.mkdir(parents=True, exist_ok=True)
    with pytest.raises(FileNotFoundError):
        T.triage_path(bad)
    assert T.delete_triage(bad) is False


@pytest.mark.parametrize("name,expected", [
    ("C:evil.txt", "evil.txt"), ("Z:x", "x"), ("report.txt:hidden", "report.txthidden"),
    ("CON", "_CON"), ("nul.txt", "_nul.txt"), ('a<b>"|?*.txt', "ab.txt"),
])
def test_safe_attachment_name_windows(name, expected):
    assert T.safe_attachment_name(name) == expected


def test_agent_reads_full_environment_and_flags_example():
    md = (Path(T.__file__).resolve().parent.parent / ".claude" / "agents" / "threat-triage.md").read_text(encoding="utf-8")
    assert "environment: .environment" in md and "inventory: .inventory" in md
    assert '"example"' in md


async def test_mcp_servers_reach_the_agent_without_secrets_on_disk(tdir, tmp_path, monkeypatch):
    from threatdesk import ai_config
    monkeypatch.setattr(ai_config, "CONFIG_PATH", tmp_path / "ai_config.json")
    ai_config.upsert_mcp_server({
        "id": "servicenow", "command": "npx", "args": ["-y", "servicenow-mcp"],
        "env": {"SN_INSTANCE": {"type": "plain", "value": "example.service-now.com"},
                "SN_TOKEN": {"type": "secret", "value": "s3cr3t-token"}},
    })
    ai_config.upsert_mcp_server({"id": "off", "command": "x", "enabled": False})
    FakeRunner.calls.clear()
    monkeypatch.setattr(T, "ClaudeRunner", FakeRunner)
    res = await T.create_triage(input_type="threat_name", input_ref="x", input_text=None, question="")
    for _ in range(100):
        await asyncio.sleep(0.01)
        if T.read_triage(res["triage_id"])["status"]["status"] in ("done", "error"):
            break
    kw = FakeRunner.calls[-1]
    cfg_path = Path(kw["mcp_config"])
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert list(cfg["mcpServers"]) == ["servicenow"]
    sn = cfg["mcpServers"]["servicenow"]
    assert sn["command"] == "npx" and sn["args"] == ["-y", "servicenow-mcp"]
    assert sn["env"] == {"SN_INSTANCE": "example.service-now.com"}
    assert "s3cr3t-token" not in cfg_path.read_text(encoding="utf-8")
    assert kw["env_overrides"]["SN_TOKEN"] == "s3cr3t-token"


async def test_no_mcp_servers_no_flag(tdir, tmp_path, monkeypatch):
    from threatdesk import ai_config
    monkeypatch.setattr(ai_config, "CONFIG_PATH", tmp_path / "ai_config.json")
    FakeRunner.calls.clear()
    monkeypatch.setattr(T, "ClaudeRunner", FakeRunner)
    await T.create_triage(input_type="threat_name", input_ref="x", input_text=None, question="")
    for _ in range(100):
        await asyncio.sleep(0.01)
        if FakeRunner.calls:
            break
    assert FakeRunner.calls[-1].get("mcp_config") is None
