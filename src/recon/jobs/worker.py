"""Worker loop: lease durable jobs and run them end-to-end.

Run one or many of these (locally or on separate machines pointed at a shared
Postgres/Redis) to scale throughput. Jobs are durable, so a crashed worker
loses nothing — the job is retried.
"""

from __future__ import annotations

import asyncio

from ..models import Query
from ..orchestrator import scan
from .base import JobQueue, get_queue


async def process(job: dict) -> None:
    if job["kind"] == "scan":
        p = job["payload"]
        await scan(Query(**p.get("query", {})), label=p.get("label"),
                   watchlist=p.get("watchlist", False))
    else:
        raise ValueError(f"unknown job kind: {job['kind']}")


async def run_worker(queue: JobQueue | None = None, poll_interval: float = 1.0,
                     once: bool = False, max_jobs: int | None = None) -> int:
    queue = queue or get_queue()
    done = 0
    while True:
        job = await asyncio.to_thread(queue.lease)
        if job is None:
            if once:
                break
            await asyncio.sleep(poll_interval)
            continue
        try:
            await process(job)
            await asyncio.to_thread(queue.complete, job["id"])
        except Exception as e:  # noqa: BLE001
            await asyncio.to_thread(queue.fail, job["id"], str(e))
        done += 1
        if max_jobs and done >= max_jobs:
            break
    return done


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
