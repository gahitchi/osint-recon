"""Behavioural tests for the IP/domain intel modules.

`test_keyed_skip.py` proves the keyed modules are *gated*; this proves that
when enabled they make the real API call and parse the real response shape
correctly (FOUND / NOT_FOUND / UNVERIFIABLE) — i.e. they are genuine
integrations, not stubs. HTTP is mocked with respx so no network is touched.
"""

import dataclasses

import httpx
import pytest
import respx

from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.http_client import RateLimitedClient
from recon.models import Query, Verdict
from recon.modules import abuseipdb, ip_geo, shodan, virustotal
from recon.modules.base import ModuleContext

_NO_ROBOTS = dataclasses.replace(SETTINGS, respect_robots=False, per_host_min_interval=0.0)


async def _run_module(mod, art):
    findings, artifacts = [], []

    async def ef(f):
        findings.append(f)

    async def ea(a):
        artifacts.append(a)

    async with RateLimitedClient(_NO_ROBOTS) as client:
        ctx = ModuleContext(client=client, query=Query(), settings=_NO_ROBOTS,
                            in_scope=lambda a: True, _emit_finding=ef, _emit_artifact=ea)
        await mod.run(art, ctx)
    return findings, artifacts


# --------------------------------------------------------------------------- shodan

@respx.mock
@pytest.mark.asyncio
async def test_shodan_parses_ports_and_emits_hostnames(monkeypatch):
    monkeypatch.setenv("RECON_KEY_SHODAN", "k")
    respx.get(url__startswith="https://api.shodan.io/shodan/host/1.1.1.1").mock(
        return_value=httpx.Response(200, json={
            "ports": [443, 80, 53], "hostnames": ["one.one.one.one"],
            "org": "Cloudflare", "os": None, "country_name": "Australia"}))

    findings, artifacts = await _run_module(
        shodan.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "1.1.1.1"))

    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].data["ports"] == [53, 80, 443]  # sorted
    assert findings[0].data["org"] == "Cloudflare"
    hostnames = {a.value for a in artifacts if a.type == ArtifactType.HOSTNAME}
    assert hostnames == {"one.one.one.one"}


@respx.mock
@pytest.mark.asyncio
async def test_shodan_404_is_not_found(monkeypatch):
    monkeypatch.setenv("RECON_KEY_SHODAN", "k")
    respx.get(url__startswith="https://api.shodan.io/shodan/host/").mock(
        return_value=httpx.Response(404, json={"error": "No information available"}))

    findings, _ = await _run_module(
        shodan.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "192.0.2.1"))
    assert findings[0].verdict == Verdict.NOT_FOUND


@respx.mock
@pytest.mark.asyncio
async def test_shodan_rate_limited_is_unverifiable(monkeypatch):
    monkeypatch.setenv("RECON_KEY_SHODAN", "k")
    respx.get(url__startswith="https://api.shodan.io/shodan/host/").mock(
        return_value=httpx.Response(429, text="slow down"))

    findings, _ = await _run_module(
        shodan.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "192.0.2.1"))
    assert findings[0].verdict == Verdict.UNVERIFIABLE


# ----------------------------------------------------------------------- virustotal

@respx.mock
@pytest.mark.asyncio
async def test_virustotal_domain_reputation(monkeypatch):
    monkeypatch.setenv("RECON_KEY_VIRUSTOTAL", "k")
    respx.get("https://www.virustotal.com/api/v3/domains/example.com").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 2, "harmless": 70},
            "reputation": -5}}}))

    findings, _ = await _run_module(
        virustotal.MODULE, Artifact.make(ArtifactType.DOMAIN, "example.com"))
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].data["reputation"] == -5
    assert findings[0].data["last_analysis_stats"]["malicious"] == 2


@respx.mock
@pytest.mark.asyncio
async def test_virustotal_ip_uses_ip_endpoint(monkeypatch):
    monkeypatch.setenv("RECON_KEY_VIRUSTOTAL", "k")
    route = respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0}, "reputation": 0}}}))

    findings, _ = await _run_module(
        virustotal.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "8.8.8.8"))
    assert route.called
    assert findings[0].verdict == Verdict.FOUND


@respx.mock
@pytest.mark.asyncio
async def test_virustotal_404_not_found_vs_error_unverifiable(monkeypatch):
    monkeypatch.setenv("RECON_KEY_VIRUSTOTAL", "k")
    respx.get(url__startswith="https://www.virustotal.com/api/v3/domains/").mock(
        return_value=httpx.Response(404))
    findings, _ = await _run_module(
        virustotal.MODULE, Artifact.make(ArtifactType.DOMAIN, "nope.invalid"))
    assert findings[0].verdict == Verdict.NOT_FOUND

    respx.get(url__startswith="https://www.virustotal.com/api/v3/domains/").mock(
        return_value=httpx.Response(401))
    findings, _ = await _run_module(
        virustotal.MODULE, Artifact.make(ArtifactType.DOMAIN, "blocked.invalid"))
    assert findings[0].verdict == Verdict.UNVERIFIABLE


# ------------------------------------------------------------------------ abuseipdb

@respx.mock
@pytest.mark.asyncio
async def test_abuseipdb_confidence_score(monkeypatch):
    monkeypatch.setenv("RECON_KEY_ABUSEIPDB", "k")
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 100, "totalReports": 42, "countryCode": "RU",
            "isp": "EvilCorp", "domain": "evil.example", "usageType": "Data Center"}}))

    findings, _ = await _run_module(
        abuseipdb.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "203.0.113.9"))
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].data["abuseConfidenceScore"] == 100
    assert findings[0].data["totalReports"] == 42
    assert any("100%" in r for r in findings[0].reasons)


@respx.mock
@pytest.mark.asyncio
async def test_abuseipdb_non_200_is_unverifiable(monkeypatch):
    monkeypatch.setenv("RECON_KEY_ABUSEIPDB", "k")
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(403, json={"errors": []}))
    findings, _ = await _run_module(
        abuseipdb.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "203.0.113.9"))
    assert findings[0].verdict == Verdict.UNVERIFIABLE


# --------------------------------------------------------------------------- ip_geo

@respx.mock
@pytest.mark.asyncio
async def test_ip_geo_success():
    respx.get(url__startswith="http://ip-api.com/json/8.8.8.8").mock(
        return_value=httpx.Response(200, json={
            "status": "success", "country": "United States", "countryCode": "US",
            "regionName": "California", "city": "Mountain View", "isp": "Google LLC",
            "org": "Google Public DNS", "as": "AS15169", "asname": "GOOGLE",
            "reverse": "dns.google", "hosting": True}))

    findings, _ = await _run_module(
        ip_geo.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "8.8.8.8"))
    assert findings[0].verdict == Verdict.FOUND
    assert findings[0].data["countryCode"] == "US"
    assert "Mountain View" in findings[0].reasons[0]


@respx.mock
@pytest.mark.asyncio
async def test_ip_geo_failure_status_is_not_found():
    respx.get(url__startswith="http://ip-api.com/json/").mock(
        return_value=httpx.Response(200, json={
            "status": "fail", "message": "reserved range"}))

    findings, _ = await _run_module(
        ip_geo.MODULE, Artifact.make(ArtifactType.IP_ADDRESS, "10.0.0.1"))
    assert findings[0].verdict == Verdict.NOT_FOUND
    assert "reserved range" in findings[0].reasons[0]
