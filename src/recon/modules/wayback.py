"""WAYBACK module: DOMAIN -> URL via the Internet Archive CDX API (keyless).

Surfaces historical/known URLs for a domain — useful for attack-surface and
content discovery — without any credentials. URLs are recorded as leaf graph
nodes (no Phase-1 module expands a raw URL), capped so the archive can't flood
the artifact budget."""

from __future__ import annotations

import json

from ..graph_models import Artifact, ArtifactType
from ..models import Finding, Verdict
from .base import Module, ModuleContext

_LIMIT = 25


async def _run(art: Artifact, ctx: ModuleContext) -> None:
    domain = art.normalized
    url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={_LIMIT}")
    try:
        resp = await ctx.client.fetch(url)
    except Exception as e:  # noqa: BLE001
        await ctx.emit_finding(Finding(
            source="wayback:cdx", category="url", label="Wayback URLs",
            url=None, verdict=Verdict.ERROR, reasons=[f"CDX query failed: {e}"]))
        return

    urls: list[str] = []
    if resp.status_code == 200 and resp.text.strip():
        try:
            rows = json.loads(resp.text)
            urls = [r[0] for r in rows[1:] if r]  # row 0 is the header
        except (json.JSONDecodeError, IndexError):
            urls = []

    await ctx.emit_finding(Finding(
        source="wayback:cdx", category="url", label="Wayback URLs",
        url=f"https://web.archive.org/cdx/search/cdx?url={domain}/*",
        verdict=Verdict.FOUND if urls else Verdict.NOT_FOUND,
        confidence=0.7 if urls else 0.0,
        reasons=[f"{len(urls)} archived URL(s)" if urls else "no archived URLs"],
        data={"urls": urls},
    ))
    for u in urls:
        await ctx.emit_artifact(Artifact.make(
            ArtifactType.URL, u, parent=art, source_module="wayback"))


MODULE = Module(
    name="wayback",
    consumes={ArtifactType.DOMAIN},
    produces={ArtifactType.URL},
    run=_run,
    reliability_prior=0.70,
)
