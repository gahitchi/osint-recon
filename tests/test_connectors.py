"""Connector resilience: caching, circuit breaker, graceful degradation."""

import pytest

from recon.connectors.base import Connector
from recon.connectors import cache
from recon.http_client import RateLimitedClient
from recon.models import Finding, Query, Verdict


def _finding(label="GitHub", verdict=Verdict.FOUND):
    return Finding(source="username", category="username", label=label,
                   url="https://x/y", verdict=verdict, confidence=1.0,
                   signals={"username:github": "alice"})


async def _drain(connector, query):
    out = []

    async def emit(f):
        out.append(f)

    async with RateLimitedClient() as client:
        await connector.run(query, client, emit)
    return out


@pytest.mark.asyncio
async def test_result_is_cached_and_replayed():
    calls = {"n": 0}

    async def collect(query, client, emit):
        calls["n"] += 1
        await emit(_finding())

    conn = Connector("fake", "username", collect, reliability_prior=0.7)
    q = Query(username="alice")

    first = await _drain(conn, q)
    second = await _drain(conn, q)  # should hit cache, not the collector

    assert calls["n"] == 1, "collector ran twice; cache not used"
    assert first[0].verdict == Verdict.FOUND
    assert any("from cache" in r for r in second[0].reasons)


@pytest.mark.asyncio
async def test_failing_source_degrades_and_opens_breaker():
    async def boom(query, client, emit):
        raise RuntimeError("source down")

    conn = Connector("flaky", "username", boom, reliability_prior=0.7, use_cache=False)
    q = Query(username="alice")

    # Enough failures to trip the breaker (threshold default 4, ratio > 0.5).
    for _ in range(5):
        out = await _drain(conn, q)
        assert out and out[-1].verdict == Verdict.ERROR  # never raises

    assert cache.breaker_open("flaky", "username", 0.7) is True


@pytest.mark.asyncio
async def test_reliability_drops_on_failure():
    async def boom(query, client, emit):
        raise RuntimeError("nope")

    conn = Connector("decayer", "username", boom, reliability_prior=0.8, use_cache=False)
    await _drain(conn, Query(username="bob"))
    assert cache.current_reliability("decayer", "username", 0.8) < 0.8
