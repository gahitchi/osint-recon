"""Scope policy + budget ceilings keep recursion bounded and on-target."""

import dataclasses

import pytest

from recon import engine as engine_mod
from recon.config import SETTINGS
from recon.engine import GraphScanEngine
from recon.graph_models import Artifact, ArtifactType
from recon.models import Query
from recon.modules.base import Module


def _chain_registry(monkeypatch, ran):
    """domain -> subdomain -> ip -> asn, recording which artifacts got processed."""
    async def domain_run(art, ctx):
        ran.append(("domain", art.normalized))
        await ctx.emit_artifact(Artifact.make(ArtifactType.SUBDOMAIN, "a.example.com",
                                              parent=art, source_module="domain"))

    async def resolve_run(art, ctx):
        ran.append(("resolve", art.normalized))
        await ctx.emit_artifact(Artifact.make(ArtifactType.IP_ADDRESS, "9.9.9.9",
                                              parent=art, source_module="resolve"))

    async def asn_run(art, ctx):
        ran.append(("asn", art.normalized))

    mods = [
        Module("domain", {ArtifactType.DOMAIN}, {ArtifactType.SUBDOMAIN}, domain_run, use_cache=False),
        Module("resolve", {ArtifactType.SUBDOMAIN}, {ArtifactType.IP_ADDRESS}, resolve_run, use_cache=False),
        Module("asn", {ArtifactType.IP_ADDRESS}, set(), asn_run, use_cache=False),
    ]
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [m for m in mods if m.accepts(art)])


async def _drain(eng):
    return [ev async for ev in eng.stream()]


@pytest.mark.asyncio
async def test_max_depth_halts_traversal(monkeypatch):
    ran = []
    _chain_registry(monkeypatch, ran)
    settings = dataclasses.replace(SETTINGS, max_depth=1)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    await _drain(eng)

    processed = {step for step, _ in ran}
    assert "domain" in processed and "resolve" in processed
    # The IP is depth 2 (> max_depth 1): recorded as a node, never processed.
    assert "asn" not in processed
    assert any(a.type == ArtifactType.IP_ADDRESS for a in eng.artifacts)


@pytest.mark.asyncio
async def test_max_artifacts_ceiling(monkeypatch):
    ran = []
    _chain_registry(monkeypatch, ran)
    settings = dataclasses.replace(SETTINGS, max_artifacts=2)
    eng = GraphScanEngine(Query(domain="example.com"), settings)
    await _drain(eng)

    assert len(eng.artifacts) <= 2
    assert eng.stop_reason == "max_artifacts reached"


@pytest.mark.asyncio
async def test_strict_scope_records_but_does_not_expand_external(monkeypatch):
    ran = []

    async def domain_run(art, ctx):
        ran.append(art.normalized)
        # Discover an UNRELATED external domain.
        await ctx.emit_artifact(Artifact.make(ArtifactType.DOMAIN, "evil-unrelated.com",
                                              parent=art, source_module="domain"))

    mod = Module("domain", {ArtifactType.DOMAIN}, {ArtifactType.DOMAIN}, domain_run, use_cache=False)
    monkeypatch.setattr(engine_mod, "applicable_modules",
                        lambda art: [mod] if mod.accepts(art) else [])

    # strict: external domain is recorded but never expanded (domain_run runs once).
    strict = dataclasses.replace(SETTINGS, scope_mode="strict")
    eng = GraphScanEngine(Query(domain="example.com"), strict)
    await _drain(eng)
    assert ran == ["example.com"]
    assert any(a.normalized == "evil-unrelated.com" for a in eng.artifacts)

    # aggressive: external domain IS expanded.
    ran.clear()
    aggressive = dataclasses.replace(SETTINGS, scope_mode="aggressive")
    eng2 = GraphScanEngine(Query(domain="example.com"), aggressive)
    await _drain(eng2)
    assert "evil-unrelated.com" in ran
