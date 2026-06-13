"""Phase 6b: the candidate-email pivot (modules/permute).

Generates email candidates from a username/name + seed domain, but only asserts
the ones a deterministic signal (Gravatar) confirms — the rest are surfaced once
as an UNCERTAIN lead and never recursed on.
"""

import dataclasses

import httpx
import pytest
import respx

from recon.collectors.email import gravatar_hash
from recon.config import SETTINGS
from recon.graph_models import Artifact, ArtifactType
from recon.http_client import RateLimitedClient
from recon.models import Query, Verdict
from recon.modules import permute
from recon.modules.base import ModuleContext

_FAST = dataclasses.replace(SETTINGS, respect_robots=False, per_host_min_interval=0.0)


async def _run(art, query):
    findings, artifacts = [], []

    async def ef(f):
        findings.append(f)

    async def ea(a):
        artifacts.append(a)

    async with RateLimitedClient(_FAST) as client:
        ctx = ModuleContext(client=client, query=query.normalized(), settings=_FAST,
                            in_scope=lambda a: True, _emit_finding=ef, _emit_artifact=ea)
        await permute.MODULE.run(art, ctx)
    return findings, artifacts


# ------------------------------------------------------------- pattern builder

def test_locals_for_username_is_just_the_handle():
    art = Artifact.make(ArtifactType.USERNAME, "jdoe")
    assert permute._locals_for(art) == ["jdoe"]


def test_locals_for_name_generates_common_patterns():
    art = Artifact.make(ArtifactType.NAME, "Jane Doe")
    locals_ = permute._locals_for(art)
    assert "jane.doe" in locals_
    assert "janedoe" in locals_
    assert "jdoe" in locals_      # first-initial + last
    assert "jane" in locals_ and "doe" in locals_


def test_clean_local_strips_punctuation_and_double_dots():
    assert permute._clean_local("Jane..Doe!") == "jane.doe"


# ----------------------------------------------------------- no domain context

@pytest.mark.asyncio
async def test_no_seed_domain_produces_nothing():
    # username-only investigation: nothing to permute against.
    findings, artifacts = await _run(
        Artifact.make(ArtifactType.USERNAME, "jdoe"), Query(username="jdoe"))
    assert findings == [] and artifacts == []


# --------------------------------------------------- gravatar-gated assertion

@respx.mock
@pytest.mark.asyncio
async def test_confirmed_candidate_emits_email_artifact_others_uncertain():
    hit = "jane.doe@acme.com"
    hit_hash = gravatar_hash(hit)

    # Gravatar 200 only for the confirmed address; 404 for every other candidate.
    respx.get(url__startswith=f"https://www.gravatar.com/avatar/{hit_hash}").mock(
        return_value=httpx.Response(200))
    respx.get(url__startswith="https://www.gravatar.com/avatar/").mock(
        return_value=httpx.Response(404))

    findings, artifacts = await _run(
        Artifact.make(ArtifactType.NAME, "Jane Doe"), Query(domain="acme.com"))

    # Exactly one verified EMAIL artifact, and it is the gravatar-confirmed one.
    emails = [a for a in artifacts if a.type == ArtifactType.EMAIL]
    assert [a.normalized for a in emails] == [hit]
    found = [f for f in findings if f.verdict == Verdict.FOUND]
    assert len(found) == 1 and found[0].label == hit
    assert found[0].signals["gravatar_hash"] == hit_hash

    # The speculative remainder is surfaced once as a single UNCERTAIN lead,
    # and is NOT turned into artifacts (no runaway recursion).
    uncertain = [f for f in findings if f.verdict == Verdict.UNCERTAIN]
    assert len(uncertain) == 1
    assert hit not in uncertain[0].data["candidates"]
    assert all(a.type == ArtifactType.EMAIL for a in artifacts)
    assert len(emails) == 1


@respx.mock
@pytest.mark.asyncio
async def test_username_plus_domain_builds_handle_at_domain():
    respx.get(url__startswith="https://www.gravatar.com/avatar/").mock(
        return_value=httpx.Response(404))
    findings, artifacts = await _run(
        Artifact.make(ArtifactType.USERNAME, "torvalds"), Query(domain="acme.com"))
    # No gravatar hit -> no artifact, one consolidated UNCERTAIN listing the candidate.
    assert artifacts == []
    assert len(findings) == 1
    assert findings[0].data["candidates"] == ["torvalds@acme.com"]
