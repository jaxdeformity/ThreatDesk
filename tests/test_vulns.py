"""Vulnerability intel: org-stack matching, search modes, tracking."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from threatdesk import vulns as V

TODAY = date.today()
KEV = [
    {"cveID": "CVE-2026-1001", "vendorProject": "Microsoft", "product": "Exchange Server",
     "vulnerabilityName": "Microsoft Exchange Server Remote Code Execution", "shortDescription": "Unauthenticated remote code execution.",
     "dateAdded": (TODAY - timedelta(days=2)).isoformat(), "dueDate": (TODAY + timedelta(days=19)).isoformat(),
     "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."},
    {"cveID": "CVE-2025-2002", "vendorProject": "Microsoft", "product": "Windows",
     "vulnerabilityName": "Microsoft Windows Kernel Elevation of Privilege", "shortDescription": "Local privilege escalation.",
     "dateAdded": "2025-03-01", "dueDate": "2025-03-22", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2024-3003", "vendorProject": "Fortinet", "product": "FortiOS",
     "vulnerabilityName": "Fortinet FortiOS SSL VPN Heap Overflow", "shortDescription": "Out-of-bounds write in SSL VPN.",
     "dateAdded": "2024-02-09", "dueDate": "2024-02-16", "knownRansomwareCampaignUse": "Unknown"},
]


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_ORG_TECH_STACK", "Microsoft Exchange, Fortinet FortiOS")
    monkeypatch.delenv("SOC_ORG_INVENTORY", raising=False)  # .env may set it when api.main was imported
    monkeypatch.setattr(V, "TRACKING_PATH", tmp_path / "t.json")


def s(q="", scope="all", news=None):
    return V.search(q, scope, news or {}, kev=KEV, use_nvd=False)


def test_stack_match_needs_every_word():
    stack = V.org_stack()
    assert V.stack_match(KEV[0], stack) == "Microsoft Exchange"
    assert V.stack_match(KEV[1], stack) is None  # Windows is Microsoft but not Exchange
    assert V.stack_match(KEV[2], stack) == "Fortinet FortiOS"


def test_stack_match_is_phrase_not_bag_of_words():
    stack = ["Microsoft Exchange", "Google Chrome", "Citrix"]
    ike = {"vendorProject": "Microsoft", "product": "Internet Key Exchange (IKE) Service Extensions"}
    assert V.stack_match(ike, stack) is None
    assert V.stack_match({"vendorProject": "Google", "product": "Chromium V8"}, stack) == "Google Chrome"
    assert V.stack_match({"vendorProject": "Citrix", "product": "NetScaler ADC"}, stack) == "Citrix"


def test_org_scope_and_counts():
    r = s(scope="org")
    assert [c["cve"] for c in r["items"]] == ["CVE-2026-1001", "CVE-2024-3003"]
    assert r["counts"]["org_affected"] == 2 and r["counts"]["org_open"] == 2 and r["counts"]["ransomware"] == 1


def test_hot_scope_uses_recent_kev_and_news():
    r = s(scope="hot", news={"CVE-2025-2002": 3})
    assert {c["cve"] for c in r["items"]} == {"CVE-2026-1001", "CVE-2025-2002"}


def test_text_search_matches_all_words():
    assert [c["cve"] for c in s("ssl vpn")["items"]] == ["CVE-2024-3003"]
    assert s("windows kernel")["items"][0]["cve"] == "CVE-2025-2002"


def test_cve_search():
    r = s("cve-2025-2002")
    assert r["mode"] == "cve" and r["items"][0]["cve"] == "CVE-2025-2002"


def test_technique_search_is_labelled_as_related():
    r = s("T1068")
    assert r["mode"] == "technique" and [c["cve"] for c in r["items"]] == ["CVE-2025-2002"]
    assert "not a CISA mapping" in r["note"]
    assert "not an exploitation technique" in s("T1059")["note"]


def test_org_matches_rank_first():
    assert s()["items"][0]["org_match"]


def test_tracking_round_trip_closes_org_item():
    V.set_tracking("cve-2026-1001", "patched", owner="IT Ops", ticket="CHG-1", note="KB applied")
    r = s(scope="org")
    assert r["counts"]["org_open"] == 1
    assert [c["cve"] for c in r["items"]] == ["CVE-2024-3003"]  # remediated items leave the open list
    assert s("CVE-2026-1001")["items"][0]["tracking"] == "patched"
    rec = V.get_tracking("CVE-2026-1001")
    assert rec["provider"] == "local" and rec["history"][-1]["note"] == "KB applied"


@pytest.mark.parametrize("cve,status", [("nope", "patched"), ("CVE-2026-1001", "done")])
def test_tracking_validation(cve, status):
    with pytest.raises(ValueError):
        V.set_tracking(cve, status)


def test_detail_offline():
    d = V.detail("CVE-2026-1001", [{"title": "Exchange bug exploited", "cves": ["CVE-2026-1001"], "link": "https://x"}],
                 kev=KEV, use_net=False)
    assert d["kev"]["ransomware"] and d["org_match"] == "Microsoft Exchange" and d["news"][0]["title"]
    assert V.detail("CVE-1999-0001", [], kev=KEV, use_net=False) is None


def test_inventory_patch_level_covers_old_kev(tmp_path, monkeypatch):
    inv = tmp_path / "inv.json"
    inv.write_text(__import__("json").dumps({"assets": [
        {"id": "INV-1", "vendor": "Microsoft", "product": "Windows Server 2022", "criticality": "crown_jewel",
         "internet_facing": False, "count": 900, "patched_through": "2025-12-31", "match": ["Microsoft Windows"]},
    ]}), encoding="utf-8")
    monkeypatch.setenv("SOC_ORG_INVENTORY", str(inv))
    monkeypatch.setenv("SOC_ORG_TECH_STACK", "")
    r = s(scope="org")
    assert r["counts"]["org_affected"] == 1 and r["counts"]["covered_by_version"] == 1 and r["counts"]["org_open"] == 0
    assert r["items"] == []
    old = s("windows kernel")["items"][0]
    assert old["exposure"]["covered"] and old["exposure"]["asset_count"] == 900


def test_vuln_news_tags_exploitation_stack_and_kev_additions(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_ORG_INVENTORY", "")
    raw = [
        {"title": "Hackers Target FortiOS Zero-Days", "link": "https://a", "source_name": "SecurityWeek",
         "published_ts": 2, "summary": "", "cves": []},
        {"title": "Weekly patch roundup", "link": "https://b", "source_name": "X", "published_ts": 1,
         "summary": "CVE-2025-2002 fixed", "cves": []},
        {"title": "Cooking with Python", "link": "https://c", "source_name": "X", "published_ts": 3, "summary": "", "cves": []},
    ]
    r = V.vuln_news(raw=raw, kev=KEV)
    titles = [i["title"] for i in r["items"]]
    assert "Cooking with Python" not in titles                        # not about vulnerabilities
    kev_story = next(i for i in r["items"] if i["kev_addition"])        # CVE-2026-1001 added 2 days ago
    assert kev_story["exploited"] and kev_story["open_in_stack"]       # Exchange is in the env stack
    forti = next(i for i in r["items"] if i["title"].startswith("Hackers"))
    assert forti["exploited"]
    roundup = next(i for i in r["items"] if i["title"] == "Weekly patch roundup")
    assert roundup["cves"][0]["cve"] == "CVE-2025-2002" and roundup["cves"][0]["kev"]
    assert V.vuln_news(raw=raw, kev=KEV, mine=True)["total"] >= 1
