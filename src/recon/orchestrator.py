"""Orchestrator: run every relevant collector concurrently against one Query,
streaming findings as they resolve and clustering them at the end.

Full automation: the caller supplies identifiers and gets a complete run with
no further interaction. Findings are pushed through an async queue so both the
CLI and the SSE server can consume the same stream.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from .config import SETTINGS
from .connectors import applicable_connectors
from .correlate import score
from .correlate.cluster import cluster
from .http_client import RateLimitedClient
from .models import Finding, Query


async def run_stream(query: Query) -> AsyncIterator[dict]:
    """Yield event dicts: {"type": "finding"|"summary"|"done"|"error", ...}.

    Each applicable source runs through its resilient Connector wrapper (cache +
    circuit breaker + reliability), so a dead source degrades gracefully.
    """
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
            connectors = [c for c in applicable_connectors(query)
                          if c.kind in SETTINGS.enabled_collectors]
            tasks = [asyncio.create_task(c.run(query, client, emit)) for c in connectors]
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


async def scan(query: Query, *, label: str | None = None, watchlist: bool = False) -> dict:
    """Durable scan: persist a Run + Observations, correlate into the identity
    graph, and diff against the previous run for change detection.

    Returns {"run_id", "target_id", "findings", "changes", "summary"}.
    """
    import asyncio

    from .store import get_db
    from .store import repo
    from .monitor.diff import diff_run
    from .correlate.graph import correlate_run

    db = get_db()
    db.create_all()
    query = query.normalized()

    # Create target + run (sync DB work off the event loop).
    def _open():
        with db.session() as s:
            target = repo.get_or_create_target(s, query, label=label, watchlist=watchlist)
            run = repo.create_run(s, target)
            return target.id, run.id

    target_id, run_id = await asyncio.to_thread(_open)

    findings: list[Finding] = []
    async for ev in run_stream(query):
        if ev["type"] == "finding":
            findings.append(Finding(**ev["finding"]))

    def _persist():
        with db.session() as s:
            run = s.get(repo.m.Run, run_id)
            for f in findings:
                repo.add_observation(s, run, f)
            repo.finish_run(s, run, "done", {
                "total": len(findings),
                "hits": sum(1 for f in findings if f.is_hit),
            })
        # Correlate + diff in their own transactions.
        entities = correlate_run(db, run_id)
        changes = diff_run(db, target_id, run_id)
        return entities, changes

    summary, changes = await asyncio.to_thread(_persist)
    return {
        "run_id": run_id,
        "target_id": target_id,
        "findings": findings,
        "summary": summary,
        "changes": changes,
    }
