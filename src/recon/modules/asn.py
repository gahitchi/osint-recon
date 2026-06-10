"""ASN module: IP_ADDRESS -> ASN / NETBLOCK / reverse-DNS HOSTNAME.

Uses the Team Cymru IP-to-ASN *DNS* service (origin.asn.cymru.com) — fully
keyless and offline-friendly (just DNS), no API key, no scraping. This is the
network-intelligence pivot that lets a person/domain investigation reach the
hosting/ASN layer the way SpiderFoot does, without commercial data sources."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.resolver
import dns.reversename

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext


def _txt(name: str) -> list[str]:
    try:
        return [str(r).strip('"') for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def _ptr(ip: str) -> list[str]:
    try:
        rev = dns.reversename.from_address(ip)
        return sorted(str(r).rstrip(".") for r in dns.resolver.resolve(rev, "PTR"))
    except Exception:
        return []


def _cymru(ip: str) -> dict:
    """Return {asn, prefix, cc, registry, as_name} via Team Cymru DNS whois."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = ".".join(reversed(addr.exploded.replace(":", "")))
        q = nibbles + ".origin6.asn.cymru.com"
    rows = _txt(q)
    if not rows:
        return {}
    # "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
    parts = [p.strip() for p in rows[0].split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else ""
    out = {"asn": asn, "prefix": parts[1] if len(parts) > 1 else "",
           "cc": parts[2] if len(parts) > 2 else "",
           "registry": parts[3] if len(parts) > 3 else ""}
    if asn:
        name_rows = _txt(f"AS{asn}.asn.cymru.com")
        if name_rows:
            np = [p.strip() for p in name_rows[0].split("|")]
            out["as_name"] = np[-1] if np else ""
    return out


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    ip = art.normalized
    info, ptr = await asyncio.gather(
        asyncio.to_thread(_cymru, ip),
        asyncio.to_thread(_ptr, ip),
    )

    if info.get("asn"):
        label = f"AS{info['asn']}" + (f" {info['as_name']}" if info.get("as_name") else "")
        await ctx.emit_finding(Finding(
            source="asn:cymru", category="network", label=label, url=None,
            verdict=Verdict.FOUND, confidence=0.9,
            reasons=[f"{ip} announced by AS{info['asn']} ({info.get('prefix', '?')})"],
            data=info,
        ))
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.ASN, info["asn"], parent=art, source_module="asn",
            as_name=info.get("as_name", ""), cc=info.get("cc", "")))
        if info.get("prefix"):
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.NETBLOCK, info["prefix"], parent=art, source_module="asn"))

    for host in ptr:
        await ctx.emit_finding(Finding(
            source="asn:rdns", category="network", label=f"rDNS {ip}", url=None,
            verdict=Verdict.FOUND, confidence=0.8,
            reasons=[f"{ip} resolves back to {host}"],
            signals={"domain": host}, data={"ip": ip, "hostname": host},
        ))
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.HOSTNAME, host, parent=art, source_module="asn"))


MODULE = Module(
    name="asn",
    consumes={ArtifactType.IP_ADDRESS},
    produces={ArtifactType.ASN, ArtifactType.NETBLOCK, ArtifactType.HOSTNAME},
    run=_run,
    reliability_prior=0.90,
)
