"""RESOLVE module: SUBDOMAIN/HOSTNAME -> IP_ADDRESS via DNS A/AAAA.

This is the first link only reachable through recursion: the domain module finds
subdomains in CT logs, the engine feeds each back here, and each resolves to IPs
that the ASN module then enriches. Reuses `collectors.domain._records` so DNS
behavior stays in one place."""

from __future__ import annotations

from ..collectors.domain import _records
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    host = art.normalized
    ips = await _records(host, "A") + await _records(host, "AAAA")
    await ctx.emit_finding(Finding(
        source="resolve:dns", category="dns", label=f"Resolve {host}",
        url=None,
        verdict=Verdict.FOUND if ips else Verdict.NOT_FOUND,
        confidence=0.95 if ips else 0.0,
        reasons=[f"{len(ips)} address(es)" if ips else "does not resolve"],
        signals={"domain": host} if ips else {},
        data={"host": host, "ips": ips},
    ))
    for ip in ips:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.IP_ADDRESS, ip, parent=art, source_module="resolve"))


MODULE = Module(
    name="resolve",
    consumes={ArtifactType.SUBDOMAIN, ArtifactType.HOSTNAME,
              ArtifactType.MX_HOST, ArtifactType.NAMESERVER},
    produces={ArtifactType.IP_ADDRESS},
    run=_run,
    reliability_prior=0.95,
)
