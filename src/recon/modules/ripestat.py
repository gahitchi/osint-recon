"""RIPEstat module: ASN -> announced NETBLOCKs; IP_ADDRESS -> network info +
abuse contact. Uses the RIPE NCC RIPEstat Data API — authoritative RIR data,
fully keyless with generous limits."""

from __future__ import annotations

import json

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_BASE = "https://stat.ripe.net/data"
_MAX_PREFIXES = 50


async def _json(ctx: ModuleContext, path: str, resource: str) -> dict:
    resp = await ctx.client.fetch(f"{_BASE}/{path}/data.json?resource={resource}")
    if resp.status_code != 200 or not resp.text.strip():
        return {}
    try:
        return json.loads(resp.text).get("data", {})
    except json.JSONDecodeError:
        return {}


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    if art.type == ArtifactType.ASN:
        data = await _json(ctx, "announced-prefixes", f"AS{art.normalized}")
        prefixes = [p.get("prefix") for p in data.get("prefixes", []) if p.get("prefix")]
        await ctx.emit_finding(Finding(
            source="ripestat:prefixes", category="network",
            label=f"AS{art.normalized} announced prefixes", url=None,
            verdict=Verdict.FOUND if prefixes else Verdict.NOT_FOUND,
            confidence=0.9 if prefixes else 0.0,
            reasons=[f"{len(prefixes)} prefix(es) announced by AS{art.normalized}"],
            data={"prefixes": prefixes[:_MAX_PREFIXES]},
        ))
        for prefix in prefixes[:_MAX_PREFIXES]:
            await ctx.emit_artifact(Artifact.make(
                ArtifactType.NETBLOCK, prefix, parent=art, source_module="ripestat"))
        return

    # IP_ADDRESS: network info + abuse contact.
    info = await _json(ctx, "network-info", art.normalized)
    asns = info.get("asns", [])
    prefix = info.get("prefix")
    abuse = await _json(ctx, "abuse-contact-finder", art.normalized)
    contacts = abuse.get("abuse_contacts", [])
    if asns or prefix or contacts:
        await ctx.emit_finding(Finding(
            source="ripestat:network", category="network",
            label=f"Network info {art.normalized}", url=None,
            verdict=Verdict.FOUND, confidence=0.9,
            reasons=[f"prefix {prefix or '?'}, AS{','.join(asns) or '?'}"
                     + (f", abuse {contacts[0]}" if contacts else "")],
            data={"asns": asns, "prefix": prefix, "abuse_contacts": contacts},
        ))
    if prefix:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.NETBLOCK, prefix, parent=art, source_module="ripestat"))


MODULE = Module(
    name="ripestat",
    consumes={ArtifactType.ASN, ArtifactType.IP_ADDRESS},
    produces={ArtifactType.NETBLOCK},
    run=_run,
    reliability_prior=0.90,
)
