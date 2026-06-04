"""FastAPI app: serves the local web UI and streams findings over SSE.

Local-first: binds 127.0.0.1 only. No data leaves the machine.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import SETTINGS
from .models import Query
from .orchestrator import run_stream

ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = ROOT / "web"

app = FastAPI(title="osint-recon", version="0.1.0")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/search")
async def search(
    username: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    domain: str | None = None,
    name: str | None = None,
) -> StreamingResponse:
    query = Query(username=username, email=email, phone=phone, domain=domain, name=name)

    async def event_gen():
        async for event in run_stream(query):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=SETTINGS.host, port=SETTINGS.port)


if __name__ == "__main__":
    main()
