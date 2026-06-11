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
from .keys import KNOWN_KEYS, VAULT
from .models import Query
from .modules.registry import MODULES
from .orchestrator import run_stream, scan
from .store import get_db, repo

# Which modules consume each known key (required gating + optional enhancement).
_OPTIONAL_KEY_USERS = {"github": ["github"], "hibp": ["breach"]}


def _modules_for_key(name: str) -> list[str]:
    used = [m.name for m in MODULES if name in m.requires_keys]
    return used or _OPTIONAL_KEY_USERS.get(name, [])

ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = ROOT / "web"

app = FastAPI(title="osint-recon", version="0.6.1")


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
             "provenance": r.provenance,
             "started_at": r.started_at.isoformat(),
             "finished_at": r.finished_at.isoformat() if r.finished_at else None}
            for r in rows
        ])


@app.get("/api/runs/{run_id}/provenance")
async def api_run_provenance(run_id: int) -> JSONResponse:
    """Run-level reproducibility stamp: tool/dataset/thresholds/engine settings the
    run was produced under (Phase 5b)."""
    with get_db().session() as s:
        run = s.get(repo.m.Run, run_id)
        if run is None:
            return JSONResponse({"error": f"run {run_id} not found"}, status_code=404)
        return JSONResponse({"run_id": run_id, "provenance": run.provenance})


@app.get("/api/targets/{target_id}/entities")
async def api_entities(target_id: int) -> JSONResponse:
    with get_db().session() as s:
        ents = repo.list_entities(s, target_id)
        return JSONResponse([
            {**_row(e, ("id", "label", "confidence")), "attributes": e.attributes,
             "flags": e.flags, "breakdown": e.breakdown,
             "confidence_shadow": (e.breakdown or {}).get("shadow_total"),
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


@app.get("/api/runs/{run_id}/graph")
async def api_run_graph(run_id: int) -> JSONResponse:
    """The discovery graph of a run: artifacts (nodes) + provenance edges,
    rendered as the dashboard's interactive force-directed Discovery map."""
    with get_db().session() as s:
        arts = repo.list_artifacts(s, run_id)
        edges = repo.list_artifact_edges(s, run_id)
        return JSONResponse({
            "run_id": run_id,
            "nodes": [
                {"id": a.id, "type": a.type, "value": a.value, "depth": a.depth,
                 "source_module": a.source_module, "confidence": a.confidence,
                 "data": a.data}
                for a in arts
            ],
            "edges": [
                {"source": e.src_artifact_id, "target": e.dst_artifact_id,
                 "module": e.module} for e in edges
            ],
        })


@app.get("/api/runs/{run_id}/rules")
async def api_run_rules(run_id: int) -> JSONResponse:
    """Insights: the declarative correlation rules that fired on this run's
    discovery graph (Phase 4), most-severe first."""
    sev = {"high": 3, "medium": 2, "low": 1, "info": 0}
    with get_db().session() as s:
        rows = repo.list_rule_findings(s, run_id)
        items = [
            {**_row(r, ("rule_id", "title", "severity", "description", "key")),
             "evidence": r.evidence, "detail": r.detail}
            for r in rows
        ]
    items.sort(key=lambda d: -sev.get(d["severity"], 0))
    return JSONResponse({"run_id": run_id, "insights": items})


@app.get("/api/rules")
async def api_rules() -> JSONResponse:
    """The correlation-rule catalogue (built-ins + any RECON_RULES_FILE)."""
    from .rules import rule_catalogue
    return JSONResponse(rule_catalogue())


@app.get("/api/sources")
async def api_sources() -> JSONResponse:
    with get_db().session() as s:
        rows = repo.list_sources(s)
        return JSONResponse([
            _row(src, ("name", "kind", "enabled", "reliability", "successes",
                       "failures", "breaker_state")) for src in rows
        ])


# --- Module catalogue ------------------------------------------------------

@app.get("/api/modules")
async def api_modules() -> JSONResponse:
    """The engine's module catalogue: what each consumes/produces, whether it
    needs keys, and whether it's currently enabled (keyless or key present)."""
    return JSONResponse([
        {
            "name": m.name,
            "consumes": sorted(t.value for t in m.consumes),
            "produces": sorted(t.value for t in m.produces),
            "keyless": not m.requires_keys,
            "requires_keys": list(m.requires_keys),
            "passive": m.passive,
            "reliability_prior": m.reliability_prior,
            "enabled": VAULT.has_all(m.requires_keys),
        }
        for m in MODULES
    ])


# --- API-key vault (local-first; values never returned) --------------------

@app.get("/api/keys")
async def api_keys() -> JSONResponse:
    """Configured/source status for each known key — never the secret value."""
    VAULT.reload()
    return JSONResponse([
        {**k, "modules": _modules_for_key(k["name"])} for k in VAULT.status()
    ])


@app.post("/api/keys")
async def api_set_key(payload: dict) -> JSONResponse:
    """Set (or clear, when value is blank) a known key in the local keys.toml."""
    name = str(payload.get("name", "")).lower()
    if name not in {k["name"] for k in KNOWN_KEYS}:
        return JSONResponse({"error": f"unknown key '{name}'"}, status_code=400)
    value = (payload.get("value") or "").strip()
    if value:
        VAULT.set(name, value)
    else:
        VAULT.clear(name)
    return JSONResponse({
        "name": name, "configured": VAULT.has(name), "source": VAULT.source(name),
    })


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def main() -> None:
    import uvicorn

    get_db()  # ensure schema exists before serving
    uvicorn.run(app, host=SETTINGS.host, port=SETTINGS.port)


if __name__ == "__main__":
    main()
