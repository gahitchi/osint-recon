"""Orchestrator: drive a recursive scan over one Query and stream findings.

The traversal itself lives in `engine.GraphScanEngine` (an event-driven graph:
seeds -> modules -> new artifacts -> modules -> ...). This module is the thin
layer that adapts the engine to the three consumers — the SSE server, the CLI,
and the durable `scan()` persistence path — and keeps the same event-dict
contract those consumers already depend on.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator

from .config import SETTINGS, Settings
from .engine import GraphScanEngine
from .models import Finding, Query


async def run_stream(query: Query, settings: Settings = SETTINGS) -> AsyncIterator[dict]:
    """Yield event dicts: {"type": "finding"|"summary"|"done"|"error", ...}.

    Each module runs through its resilient wrapper (cache + circuit breaker +
    reliability), so a dead source degrades gracefully and recursion proceeds."""
    engine = GraphScanEngine(query, settings)
    async for event in engine.stream():
        yield event


async def run_collect(query: Query, settings: Settings = SETTINGS) -> dict:
    """Non-streaming convenience: run fully and return all findings + summary."""
    findings: list[Finding] = []
    summary: dict = {}
    async for ev in run_stream(query, settings):
        if ev["type"] == "finding":
            findings.append(Finding(**ev["finding"]))
        elif ev["type"] == "summary":
            summary = ev["summary"]
    return {"findings": findings, "summary": summary}


async def scan(query: Query, *, label: str | None = None, watchlist: bool = False,
               settings: Settings = SETTINGS) -> dict:
    """Durable scan: persist a Run + Observations + the discovery graph, correlate
    into the identity graph, and diff against the previous run for change detection.

    Returns {"run_id", "target_id", "findings", "summary", "changes",
             "artifacts", "edges", "stop_reason"}.
    """
    from .correlate.graph import correlate_run
    from .monitor.diff import diff_run
    from .store import get_db, repo

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

    engine = GraphScanEngine(query, settings)
    findings: list[Finding] = []
    async for ev in engine.stream():
        if ev["type"] == "finding":
            findings.append(Finding(**ev["finding"]))

    def _persist():
        with db.session() as s:
            run = s.get(repo.m.Run, run_id)
            for f in findings:
                repo.add_observation(s, run, f,
                                     reliability=float(f.data.get("source_reliability", 0.5)))
            repo.persist_graph(s, run, engine.artifacts, engine.edges)
            repo.finish_run(s, run, "done", {
                "total": len(findings),
                "hits": sum(1 for f in findings if f.is_hit),
                "artifacts": len(engine.artifacts),
                "stop_reason": engine.stop_reason,
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
        "artifacts": engine.artifacts,
        "edges": engine.edges,
        "stop_reason": engine.stop_reason,
    }
