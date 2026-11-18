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
