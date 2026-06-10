"""CommonCrawl module: DOMAIN -> known URLs from the latest CommonCrawl index
(keyless). Complements `wayback.py` with a second historical-URL source. URLs
are recorded as leaf nodes, capped so the index can't flood the budget."""

from __future__ import annotations

import json

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_LIMIT = 25


async def _latest_index(ctx: ModuleContext) -> str | None:
    resp = await ctx.client.fetch("https://index.commoncrawl.org/collinfo.json")
    if resp.status_code != 200:
        return None
    try:
        cols = json.loads(resp.text)
        return cols[0]["cdx-api"] if cols else None
    except (json.JSONDecodeError, KeyError, IndexError):
        return None


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    domain = art.normalized
    api = await _latest_index(ctx)
    if not api:
        await ctx.emit_finding(Finding(
            source="commoncrawl:cdx", category="url", label="CommonCrawl URLs",
            verdict=Verdict.ERROR, reasons=["could not resolve latest CC index"]))
        return

    resp = await ctx.client.fetch(f"{api}?url={domain}/*&output=json&limit={_LIMIT}")
    urls: list[str] = []
    if resp.status_code == 200 and resp.text.strip():
        for line in resp.text.splitlines():
            try:
                u = json.loads(line).get("url")
            except json.JSONDecodeError:
                continue
            if u:
                urls.append(u)

    await ctx.emit_finding(Finding(
        source="commoncrawl:cdx", category="url", label="CommonCrawl URLs", url=None,
        verdict=Verdict.FOUND if urls else Verdict.NOT_FOUND,
        confidence=0.7 if urls else 0.0,
        reasons=[f"{len(urls)} URL(s) in CommonCrawl" if urls else "no CommonCrawl URLs"],
        data={"urls": urls},
    ))
    for u in urls:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.URL, u, parent=art, source_module="commoncrawl"))


MODULE = Module(
    name="commoncrawl",
    consumes={ArtifactType.DOMAIN},
    produces={ArtifactType.URL},
    run=_run,
    reliability_prior=0.70,
)
