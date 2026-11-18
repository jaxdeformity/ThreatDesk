"""Threat-intel / OSINT service keys: encrypted at rest, never echoed,
exported to the environment for enrichers and agents."""

from __future__ import annotations

import json
import os
import sys

import pytest

from threatdesk import service_keys as sk

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI store is Windows-only")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(sk, "STORE_PATH", tmp_path / "service_keys.json")
    monkeypatch.setattr(sk, "_ORIGINAL_ENV", set())
    for c in sk.CATALOG:
        monkeypatch.delenv(c["env"], raising=False)
    monkeypatch.delenv("MY_FEED_KEY", raising=False)
    return tmp_path / "service_keys.json"


def test_set_key_encrypts_and_exports(store):
    k = sk.set_key("shodan", "abcd1234WXYZ")
    assert k["configured"] and k["last4"] == "WXYZ" and k["source"] == "settings"
    raw = store.read_text(encoding="utf-8")
    assert "abcd1234WXYZ" not in raw  # encrypted at rest
    assert os.environ["SHODAN_API_KEY"] == "abcd1234WXYZ"
    assert all("value" not in e and "blob" not in e for e in sk.list_keys())


def test_clear_key_removes_env(store):
    sk.set_key("greynoise", "k1")
    sk.set_key("greynoise", "")
    assert "GREYNOISE_API_KEY" not in os.environ
    assert not next(k for k in sk.list_keys() if k["id"] == "greynoise")["configured"]


def test_real_env_wins_and_is_reported(store, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "from-env")
    monkeypatch.setattr(sk, "_ORIGINAL_ENV", {"VT_API_KEY"})
    sk.set_key("virustotal", "from-settings")
    assert os.environ["VT_API_KEY"] == "from-env"
    assert next(k for k in sk.list_keys() if k["id"] == "virustotal")["source"] == "env"


def test_load_into_environment_after_restart(store):
    sk.set_key("urlscan", "u-key")
    os.environ.pop("URLSCAN_API_KEY")
    assert sk.load_into_environment() == ["urlscan"]
    assert os.environ["URLSCAN_API_KEY"] == "u-key"


def test_custom_service(store):
    sk.add_custom("myfeed", "My feed", "MY_FEED_KEY")
    sk.set_key("myfeed", "f-key")
    assert os.environ["MY_FEED_KEY"] == "f-key"
    sk.delete_custom("myfeed")
    assert "MY_FEED_KEY" not in os.environ


@pytest.mark.parametrize("env", ["ANTHROPIC_API_KEY", "PATH", "1BAD", "OPENAI_API_KEY"])
def test_custom_cannot_hijack_reserved_env(store, env):
    with pytest.raises(ValueError):
        sk.add_custom("bad", "bad", env)


def test_import_honeyhive_secrets_json_fills_only_empty(store, tmp_path):
    sk.set_key("shodan", "keep-me")
    f = tmp_path / "secrets.json"
    f.write_text(json.dumps({"shodan": "other", "greynoise": "g", "anthropic": "sk-ant-x", "vt": "v"}), encoding="utf-8")
    got = sk.import_file(f)
    assert sorted(got) == ["greynoise", "virustotal"]  # anthropic is never imported here
    assert os.environ["SHODAN_API_KEY"] == "keep-me"


def test_import_notes_file(store, tmp_path):
    f = tmp_path / "keys.md"
    f.write_text("Shodan: s1\nAbuseIPDB = a1\nrandom prose line\n", encoding="utf-8")
    assert sorted(sk.import_file(f)) == ["abuseipdb", "shodan"]
