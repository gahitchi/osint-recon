"""Durable job queue + worker loop (no network: scan is stubbed)."""

import pytest

from recon.jobs.base import LocalQueue
from recon.jobs import worker as worker_mod


@pytest.mark.asyncio
async def test_enqueue_lease_complete_roundtrip():
    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "alice"}})
    assert q.status(jid) == "queued"

    leased = q.lease()
    assert leased["id"] == jid and leased["kind"] == "scan"
    assert q.status(jid) == "leased"
    assert q.lease() is None  # nothing else queued

    q.complete(jid)
    assert q.status(jid) == "done"


@pytest.mark.asyncio
async def test_worker_processes_job(monkeypatch):
    seen = []

    async def fake_scan(query, **kw):
        seen.append(query.username)
        return {"run_id": 1}

    monkeypatch.setattr(worker_mod, "scan", fake_scan)

    q = LocalQueue()
    q.enqueue("scan", {"query": {"username": "bob"}})
    processed = await worker_mod.run_worker(q, once=True, max_jobs=1)

    assert processed == 1
    assert seen == ["bob"]


@pytest.mark.asyncio
async def test_failed_job_is_retried_then_errored(monkeypatch):
    async def boom(query, **kw):
        raise RuntimeError("down")

    monkeypatch.setattr(worker_mod, "scan", boom)
    q = LocalQueue()
    jid = q.enqueue("scan", {"query": {"username": "z"}})

    # attempts 1,2,3 -> requeued; on the 3rd failure it errors out.
    for _ in range(3):
        job = q.lease()
        assert job is not None
        try:
            await worker_mod.process(job)
        except Exception as e:  # noqa: BLE001
            q.fail(job["id"], str(e))
    assert q.status(jid) == "error"
