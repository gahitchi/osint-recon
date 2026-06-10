"""The adapted modules forward the underlying collector's findings unchanged and
emit the right pivot artifacts (the 'no behavior change' guarantee)."""

import pytest

from recon.collectors import domain as domain_collector
from recon.collectors import username as username_collector
from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.models import Finding, Query, Verdict
from recon.modules import domain as domain_mod
from recon.modules import username as username_mod
from recon.modules.base import ModuleContext


def _ctx(findings, artifacts):
    async def ef(f):
        findings.append(f)

    async def ea(a):
        artifacts.append(a)

    return ModuleContext(client=None, query=Query(), settings=SETTINGS,
                         in_scope=lambda a: True, _emit_finding=ef, _emit_artifact=ea)


@pytest.mark.asyncio
async def test_username_module_forwards_findings_and_pivots(monkeypatch):
    sample = [
        Finding(source="username:GitHub", category="username", label="GitHub",
                url="https://github.com/alice", verdict=Verdict.FOUND, confidence=0.9),
        Finding(source="username:Reddit", category="username", label="Reddit",
                url="https://reddit.com/u/alice", verdict=Verdict.NOT_FOUND),
    ]

    async def fake_collect(query, client, emit):
        for f in sample:
            await emit(f)

    monkeypatch.setattr(username_collector, "collect", fake_collect)

    findings, artifacts = [], []
    await username_mod.MODULE.run(
        Artifact.make(ArtifactType.USERNAME, "alice"), _ctx(findings, artifacts))

    # Every collector finding is forwarded, unchanged and in order.
    assert [f.source for f in findings] == ["username:GitHub", "username:Reddit"]
    # Only the FOUND-with-url site becomes an ACCOUNT_PROFILE pivot.
    profiles = [a for a in artifacts if a.type == ArtifactType.ACCOUNT_PROFILE]
    assert len(profiles) == 1
    assert profiles[0].value == "https://github.com/alice"


@pytest.mark.asyncio
async def test_domain_module_emits_typed_artifacts(monkeypatch):
    async def fake_collect(query, client, emit):
        await emit(Finding(
            source="domain:dns", category="domain", label="DNS", verdict=Verdict.FOUND,
            data={"A": ["93.184.216.34"], "AAAA": [], "MX": ["10 mail.example.com"],
                  "NS": ["ns1.example.com"], "TXT": []}))
        await emit(Finding(
            source="domain:crtsh", category="domain", label="Subdomains", verdict=Verdict.FOUND,
            data={"subdomains": ["www.example.com", "api.example.com"]}))

    monkeypatch.setattr(domain_collector, "collect", fake_collect)

    findings, artifacts = [], []
    await domain_mod.MODULE.run(
        Artifact.make(ArtifactType.DOMAIN, "example.com"), _ctx(findings, artifacts))

    kinds = {a.type for a in artifacts}
    assert ArtifactType.IP_ADDRESS in kinds
    assert ArtifactType.MX_HOST in kinds
    assert ArtifactType.NAMESERVER in kinds
    assert ArtifactType.SUBDOMAIN in kinds
    # MX host is extracted from the "10 mail.example.com" priority form.
    mx = [a.value for a in artifacts if a.type == ArtifactType.MX_HOST]
    assert mx == ["mail.example.com"]
    subs = {a.value for a in artifacts if a.type == ArtifactType.SUBDOMAIN}
    assert subs == {"www.example.com", "api.example.com"}
