"""Optional Redis/arq-backed queue for distributed workers.

Kept import-guarded so the core install stays local-first. Enqueue still records
a durable Job row (provenance/resumability); arq handles cross-machine dispatch.
Install with: pip install -e ".[distributed]" and set queue_backend = "arq".
"""

from __future__ import annotations

import os
from typing import Any, Optional

from .base import JobQueue, LocalQueue


class ArqQueue(JobQueue):
    def __init__(self) -> None:
        # Import here so the dependency is only needed on the scale path.
        from arq import create_pool  # noqa: F401
        from arq.connections import RedisSettings  # noqa: F401

        self._redis_dsn = os.environ.get("RECON_REDIS_DSN", "redis://localhost:6379")
        self._local = LocalQueue()  # durable record of jobs

    def enqueue(self, kind: str, payload: dict[str, Any], run_id: int | None = None) -> int:
        import asyncio

        from arq import create_pool
        from arq.connections import RedisSettings

        job_id = self._local.enqueue(kind, payload, run_id)

        async def _push():
            pool = await create_pool(RedisSettings.from_dsn(self._redis_dsn))
            await pool.enqueue_job("run_scan_job", job_id, kind, payload)

        asyncio.get_event_loop().run_until_complete(_push())
        return job_id

    # Workers pull via arq's own runner; these mirror local bookkeeping.
    def lease(self) -> Optional[dict]:
        return self._local.lease()

    def complete(self, job_id: int) -> None:
        self._local.complete(job_id)

    def fail(self, job_id: int, error: str) -> None:
        self._local.fail(job_id, error)

    def status(self, job_id: int) -> Optional[str]:
        return self._local.status(job_id)
