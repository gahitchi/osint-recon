"""Orchestrator: run every relevant collector concurrently against one Query,
streaming findings as they resolve and clustering them at the end.

Full automation: the caller supplies identifiers and gets a complete run with
no further interaction. Findings are pushed through an async queue so both the
CLI and the SSE server can consume the same stream.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from .collectors import domain, email, name, phone, username
from .config import SETTINGS
from .correlate import score
from .correlate.cluster import cluster
from .http_client import RateLimitedClient
from .models import Finding, Query

_COLLECTORS = {
    "username": username.collect,
    "email": email.collect,
    "phone": phone.collect,
    "domain": domain.collect,
    "name": name.collect,
}


async def run_stream(query: Query) -> AsyncIterator[dict]:
    """Yield event dicts: {"type": "finding"|"summary"|"done"|"error", ...}."""
    query = query.normalized()
    if query.is_empty():
        yield {"type": "error", "message": "no identifiers provided"}
        return

    queue: asyncio.Queue = asyncio.Queue()
    collected: list[Finding] = []

    async def emit(f: Finding) -> None:
        await queue.put(f)

    async def worker() -> None:
        async with RateLimitedClient(SETTINGS) as client:
            tasks = []
            for key in SETTINGS.enabled_collectors:
                collect = _COLLECTORS.get(key)
                if collect is None:
                    continue
                tasks.append(asyncio.create_task(collect(query, client, emit)))
            await asyncio.gather(*tasks, return_exceptions=True)
        await queue.put(None)  # sentinel

    task = asyncio.create_task(worker())
    try:
        while True:
            item = await queue.get()
            if item is None:
                break
            collected.append(item)
            yield {"type": "finding", "finding": item.model_dump()}
    finally:
        await task

    identities = cluster([f for f in collected if f.is_hit])
    yield {"type": "summary", "summary": score.summarize(identities)}
    yield {"type": "done", "total": len(collected),
           "hits": sum(1 for f in collected if f.is_hit)}


async def run_collect(query: Query) -> dict:
    """Non-streaming convenience: run fully and return all findings + summary."""
    findings: list[Finding] = []
    summary: dict = {}
    async for ev in run_stream(query):
        if ev["type"] == "finding":
            findings.append(Finding(**ev["finding"]))
        elif ev["type"] == "summary":
            summary = ev["summary"]
    return {"findings": findings, "summary": summary}
