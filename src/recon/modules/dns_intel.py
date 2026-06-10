"""DNS intelligence module: DOMAIN -> mail-security posture (SPF/DMARC), CAA, SOA,
and the related infrastructure named in SPF (include:/ip4:/ip6:/redirect=).

This deepens the domain branch of the graph the way SpiderFoot's DNS modules do,
but every emitted host/IP still passes through the scope policy before it expands.
Reuses the offline-DNS pattern from `collectors/domain.py` / `modules/asn.py`."""

from __future__ import annotations

import asyncio

import dns.resolver

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


def _txt(name: str) -> list[str]:
    try:
        return [str(r).strip('"').replace('" "', "") for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def _records(name: str, rtype: str) -> list[str]:
    try:
        return [str(r) for r in dns.resolver.resolve(name, rtype)]
    except Exception:
        return []


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    domain = art.normalized
    txt, dmarc, caa, soa = await asyncio.gather(
        asyncio.to_thread(_txt, domain),
        asyncio.to_thread(_txt, f"_dmarc.{domain}"),
        asyncio.to_thread(_records, domain, "CAA"),
        asyncio.to_thread(_records, domain, "SOA"),
    )

    # --- SPF ---
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    if spf:
        policy = ("strict (-all)" if "-all" in spf else
                  "soft (~all)" if "~all" in spf else "permissive")
        await ctx.emit_finding(Finding(
            source="dns:spf", category="dns", label=f"SPF {domain}", url=None,
            verdict=Verdict.FOUND, confidence=0.9,
            reasons=[f"SPF present, {policy}"], data={"spf": spf}))
        for tok in spf.split():
            tok = tok.strip()
            if tok.startswith("include:") or tok.startswith("redirect="):
                host = tok.split(":", 1)[-1].split("=", 1)[-1]
                await ctx.emit_artifact(Artifact.make(
                    ArtifactType.DOMAIN, host, parent=art, source_module="dns_intel"))
            elif tok.startswith("ip4:") or tok.startswith("ip6:"):
                val = tok.split(":", 1)[1]
                atype = ArtifactType.NETBLOCK if "/" in val else ArtifactType.IP_ADDRESS
                await ctx.emit_artifact(Artifact.make(
                    atype, val, parent=art, source_module="dns_intel"))
    else:
        await ctx.emit_finding(Finding(
            source="dns:spf", category="dns", label=f"SPF {domain}",
            verdict=Verdict.NOT_FOUND, reasons=["no SPF record (spoofable sender domain)"]))

    # --- DMARC ---
    dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    if dmarc_rec:
        pol = next((p.split("=", 1)[1] for p in dmarc_rec.split(";")
                    if p.strip().startswith("p=")), "none")
        await ctx.emit_finding(Finding(
            source="dns:dmarc", category="dns", label=f"DMARC {domain}", url=None,
            verdict=Verdict.FOUND, confidence=0.9,
            reasons=[f"DMARC policy p={pol}"], data={"dmarc": dmarc_rec}))
    else:
        await ctx.emit_finding(Finding(
            source="dns:dmarc", category="dns", label=f"DMARC {domain}",
            verdict=Verdict.NOT_FOUND, reasons=["no DMARC record"]))

    # --- CAA / SOA (informational) ---
    if caa:
        await ctx.emit_finding(Finding(
            source="dns:caa", category="dns", label=f"CAA {domain}", url=None,
            verdict=Verdict.FOUND, confidence=0.8,
            reasons=[f"{len(caa)} CAA record(s)"], data={"caa": caa}))
    if soa:
        await ctx.emit_finding(Finding(
            source="dns:soa", category="dns", label=f"SOA {domain}", url=None,
            verdict=Verdict.FOUND, confidence=0.8,
            reasons=[soa[0]], data={"soa": soa[0]}))


MODULE = Module(
    name="dns_intel",
    consumes={ArtifactType.DOMAIN},
    produces={ArtifactType.DOMAIN, ArtifactType.IP_ADDRESS, ArtifactType.NETBLOCK},
    run=_run,
    reliability_prior=0.90,
)
