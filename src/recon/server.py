"""FastAPI app: local web UI + JSON API for investigations, monitoring timeline,
the identity graph, and source health. Streams live findings over SSE.

Local-first: binds 127.0.0.1 only. No data leaves the machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import SETTINGS
from .models import Query
from .orchestrator import run_stream, scan
from .store import get_db, repo

ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = ROOT / "web"

app = FastAPI(title="osint-recon", version="0.2.0")


def _row(obj: Any, fields: tuple[str, ...]) -> dict:
    return {f: getattr(obj, f) for f in fields}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


# --- Live search (SSE) -----------------------------------------------------

@app.get("/api/search")
async def search(username: str | None = None, email: str | None = None,
                 phone: str | None = None, domain: str | None = None,
                 name: str | None = None) -> StreamingResponse:
    query = Query(username=username, email=email, phone=phone, domain=domain, name=name)

    async def event_gen():
        async for event in run_stream(query):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --- Durable, persisted scan (correlate + diff) ----------------------------

@app.post("/api/scan")
async def api_scan(payload: dict) -> JSONResponse:
    q = Query(**{k: payload.get(k) for k in ("username", "email", "phone", "domain", "name")})
    result = await scan(q, label=payload.get("label"), watchlist=bool(payload.get("watchlist")))
    return JSONResponse({
        "run_id": result["run_id"], "target_id": result["target_id"],
        "summary": result["summary"], "changes": result["changes"],
        "hits": sum(1 for f in result["findings"] if f.is_hit),
    })


# --- Investigation data ----------------------------------------------------

@app.get("/api/targets")
async def api_targets(watchlist: bool = False) -> JSONResponse:
    with get_db().session() as s:
        rows = repo.list_targets(s, watchlist_only=watchlist)
        return JSONResponse([
            {**_row(t, ("id", "label", "watchlist")), "query": t.query,
             "created_at": t.created_at.isoformat()} for t in rows
        ])


@app.get("/api/runs")
async def api_runs(target_id: int | None = None) -> JSONResponse:
    with get_db().session() as s:
        rows = repo.list_runs(s, target_id=target_id)
        return JSONResponse([
            {**_row(r, ("id", "target_id", "status")), "stats": r.stats,
             "started_at": r.started_at.isoformat(),
             "finished_at": r.finished_at.isoformat() if r.finished_at else None}
            for r in rows
        ])


@app.get("/api/targets/{target_id}/entities")
async def api_entities(target_id: int) -> JSONResponse:
    with get_db().session() as s:
        ents = repo.list_entities(s, target_id)
        return JSONResponse([
            {**_row(e, ("id", "label", "confidence")), "attributes": e.attributes,
             "flags": e.flags,
             "sources": sorted({o.source for o in e.observations})}
            for e in ents
        ])


@app.get("/api/changes")
async def api_changes_all(target_id: int | None = None) -> JSONResponse:
    with get_db().session() as s:
        rows = repo.list_changes(s, target_id=target_id)
        return JSONResponse([
            {**_row(c, ("id", "kind", "source", "label")), "target_id": c.target_id,
             "detail": c.detail, "created_at": c.created_at.isoformat()} for c in rows
        ])


@app.get("/api/targets/{target_id}/changes")
async def api_changes(target_id: int) -> JSONResponse:
    return await api_changes_all(target_id=target_id)


@app.get("/api/sources")
async def api_sources() -> JSONResponse:
    with get_db().session() as s:
        rows = repo.list_sources(s)
        return JSONResponse([
            _row(src, ("name", "kind", "enabled", "reliability", "successes",
                       "failures", "breaker_state")) for src in rows
        ])


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def main() -> None:
    import uvicorn

    get_db()  # ensure schema exists before serving
    uvicorn.run(app, host=SETTINGS.host, port=SETTINGS.port)


if __name__ == "__main__":
    main()
