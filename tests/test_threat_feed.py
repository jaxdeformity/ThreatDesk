from threatdesk import threat_feed as F


async def test_total_outage_keeps_previous_items(monkeypatch):
    monkeypatch.setattr(F._cache, "items", [{"title": "kept"}])
    monkeypatch.setattr(F._cache, "kev_cves", {"CVE-2024-3400"})
    monkeypatch.setattr(F._cache, "last_refreshed_at", 1.0)

    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(F, "_fetch_source", boom)
    monkeypatch.setattr(F, "_fetch_kev", boom)
    await F._refresh()
    assert F._cache.items == [{"title": "kept"}]
    assert F._cache.kev_cves == {"CVE-2024-3400"}
    assert all(not s["ok"] for s in F._cache.source_status.values())
    assert F._cache.refreshing is False
    # retry sooner than the full TTL rather than serving a stale 30-min window
    assert F._cache.last_refreshed_at == 1.0


async def test_outage_backoff_skips_refetch(monkeypatch):
    calls = []

    async def fake_refresh():
        calls.append(1)

    monkeypatch.setattr(F, "_refresh", fake_refresh)
    monkeypatch.setattr(F._cache, "last_refreshed_at", 0.0)
    monkeypatch.setattr(F._cache, "last_failed_at", F.time.time())
    await F.get_feed()
    assert calls == []
    await F.get_feed(force=True)
    assert calls == [1]
