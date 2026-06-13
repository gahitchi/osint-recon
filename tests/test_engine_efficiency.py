"""Phase 6a: efficient traversal.

Covers (1) the honest request budget — measured in real outbound requests
counted by the client, not module dispatches — and (2) the priority frontier
that expands high-yield leads before low-value breadcrumbs when the budget is
tight.
"""

import dataclasses

import httpx
import pytest
import respx

from recon import engine as engine_mod
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.http_client import RateLimitedClient
from recon.models import Query
from recon.modules.base import Module

_FAST = dataclasses.replace(SETTINGS, respect_robots=False, per_host_min_interval=0.0)


# --------------------------------------------------------------- priority key

def test_priority_orders_identity_types_above_breadcrumbs():
    p = GraphScanEngine._priority
    email = Artifact.make(ArtifactType.EMAIL, "a@b.com")
    ip = Artifact.make(ArtifactType.IP_ADDRESS, "1.1.1.1")
    name = Artifact.make(ArtifactType.NAME, "Jane Doe")
    # EMAIL (identity-bearing) outranks an IP, which outranks a bare NAME.
    assert p(email) > p(ip) > p(name)


def test_priority_breaks_ties_on_confidence_then_depth():
    p = GraphScanEngine._priority
    seed = Artifact.make(ArtifactType.DOMAIN, "example.com")
    hi = Artifact.make(ArtifactType.SUBDOMAIN, "a.example.com", parent=seed, confidence=0.9)
    lo = Artifact.make(ArtifactType.SUBDOMAIN, "b.example.com", parent=seed, confidence=0.3)
    assert p(hi) > p(lo)  # same type + depth -> higher confidence wins


# ---------------------------------------------------------- real-request count

@respx.mock
@pytest.mark.asyncio
async def test_client_counts_real_requests():
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    async with RateLimitedClient(_FAST) as client:
        assert client.request_count == 0
        await client.fetch("https://example.com/a")
        await client.fetch("https://example.com/b")
        assert client.request_count == 2


# ----------------------------------------------------- budget halts expansion

@respx.mock
@pytest.mark.asyncio
async def test_request_budget_counts_fetches_and_halts_next_wave(monkeypatch):
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    calls = {"resolve": []}

    async def domain_run(art, ctx):
        # Three *real* requests in a single module dispatch.
        for i in range(3):
            await ctx.client.fetch(f"https://h{i}.example.com/")
        await ctx.emit_artifact(Artifact.make(ArtifactType.SUBDOMAIN, "a.example.com",
                                              parent=art, source_module="domain"))

    async def resolve_run(art, ctx):
        calls["resolve"].append(art.normalized)

    mods = [
        Module("domain", {ArtifactType.DOMAIN}, {ArtifactType.SUBDOMAIN}, domain_run, use_cache=False),
        Module("resolve", {ArtifactType.SUBDOMAIN}, set(), resolve_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])

    # Budget of 2 real requests: the domain wave makes 3, so the resolve wave
    # never starts. (A dispatch-counting budget would have allowed it.)
    settings = dataclasses.replace(_FAST, max_requests=2)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    [ev async for ev in eng.stream()]

    assert calls["resolve"] == []                       # next wave halted
    assert eng.stop_reason == "max_requests reached"


@respx.mock
@pytest.mark.asyncio
async def test_high_priority_lead_expands_before_low_when_budget_tight(monkeypatch):
    """Within one wave, a tight budget must spend itself on the EMAIL lead
    (high priority) and skip the IP breadcrumb (low priority)."""
    respx.route().mock(return_value=httpx.Response(200, text="ok"))
    expanded = []

    async def seed_run(art, ctx):
        # Emit one low-value and one high-value lead in the same wave.
        await ctx.emit_artifact(Artifact.make(ArtifactType.IP_ADDRESS, "9.9.9.9",
                                              parent=art, source_module="seed_mod"))
        await ctx.emit_artifact(Artifact.make(ArtifactType.EMAIL, "found@example.com",
                                              parent=art, source_module="seed_mod"))

    async def ip_run(art, ctx):
        expanded.append("ip")
        await ctx.client.fetch("https://ip.example.com/")

    async def email_run(art, ctx):
        expanded.append("email")
        await ctx.client.fetch("https://email.example.com/")

    mods = [
        Module("seed_mod", {ArtifactType.DOMAIN}, set(), seed_run, use_cache=False),
        Module("ip_mod", {ArtifactType.IP_ADDRESS}, set(), ip_run, use_cache=False),
        Module("email_mod", {ArtifactType.EMAIL}, set(), email_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])

    # The seed module makes no request, so the second wave starts with budget
    # fully intact. max_concurrency=1 -> one dispatch per batch; max_requests=1
    # leaves room for exactly one of the two leads. Priority must spend it on
    # the EMAIL and skip the IP.
    settings = dataclasses.replace(_FAST, max_requests=1, max_concurrency=1)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    [ev async for ev in eng.stream()]

    assert expanded == ["email"]                        # high-yield lead won the budget
    assert eng.stop_reason == "max_requests reached"
