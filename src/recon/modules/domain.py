"""DOMAIN module: DNS + RDAP + crt.sh (via the existing collector), then pivot
every discovered record into typed artifacts — subdomains, A/AAAA IPs, MX hosts,
and nameservers — so resolution/ASN enrichment and recursive subdomain scanning
can follow."""

from __future__ import annotations

from ..collectors import domain as _domain
from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Query
from .base import Module, ModuleContext

# Be polite: cap how many subdomains one domain injects into the frontier so a
# huge CT footprint can't, on its own, exhaust the artifact budget.
_MAX_SUBDOMAINS = 50


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    q = Query(domain=art.normalized)

    async def emit(f: Finding) -> None:
        await ctx.emit_finding(f)
        if f.source == "domain:dns":
            for ip in f.data.get("A", []) + f.data.get("AAAA", []):
                await ctx.emit_artifact(Artifact.make(
                    ArtifactType.IP_ADDRESS, ip, parent=art, source_module="domain"))
            for mx in f.data.get("MX", []):
                host = (mx.split()[-1] if mx else "").strip(".")  # "10 mail.x.com" -> host
                if "." in host:  # skip null MX (RFC 7505: "0 .") and junk
                    await ctx.emit_artifact(Artifact.make(
                        ArtifactType.MX_HOST, host, parent=art, source_module="domain"))
            for ns in f.data.get("NS", []):
                await ctx.emit_artifact(Artifact.make(
                    ArtifactType.NAMESERVER, ns, parent=art, source_module="domain"))
        elif f.source == "domain:crtsh":
            for sub in f.data.get("subdomains", [])[:_MAX_SUBDOMAINS]:
                await ctx.emit_artifact(Artifact.make(
                    ArtifactType.SUBDOMAIN, sub, parent=art, source_module="domain"))

    await _domain.collect(q, ctx.client, emit)


MODULE = Module(
    name="domain",
    consumes={ArtifactType.DOMAIN},
    produces={ArtifactType.SUBDOMAIN, ArtifactType.IP_ADDRESS,
              ArtifactType.MX_HOST, ArtifactType.NAMESERVER},
    run=_run,
    reliability_prior=0.90,
)
