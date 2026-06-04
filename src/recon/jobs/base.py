"""Job queue interface + durable Store-backed local implementation.

LocalQueue leases jobs from the `jobs` table. On SQLite (single writer) leasing
is naturally serialized; on Postgres a worker fleet should lease with
`SELECT ... FOR UPDATE SKIP LOCKED` (noted in `lease()`), giving horizontal
scale with no code change above this layer.
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from typing import Any, Optional

from sqlalchemy import select

from ..config import SETTINGS
from ..store import get_db
from ..store import models_db as m


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class JobQueue(ABC):
    @abstractmethod
    def enqueue(self, kind: str, payload: dict[str, Any], run_id: int | None = None) -> int: ...

    @abstractmethod
    def lease(self) -> Optional[dict]: ...

    @abstractmethod
    def complete(self, job_id: int) -> None: ...

    @abstractmethod
    def fail(self, job_id: int, error: str) -> None: ...

    @abstractmethod
    def status(self, job_id: int) -> Optional[str]: ...


class LocalQueue(JobQueue):
    def enqueue(self, kind: str, payload: dict[str, Any], run_id: int | None = None) -> int:
        with get_db().session() as s:
            job = m.Job(kind=kind, payload=payload, run_id=run_id, status="queued")
            s.add(job)
            s.flush()
            return job.id

    def lease(self) -> Optional[dict]:
        with get_db().session() as s:
            # On Postgres, add .with_for_update(skip_locked=True) for safe fan-out.
            job = s.execute(
                select(m.Job).where(m.Job.status == "queued")
                .order_by(m.Job.id).limit(1)
            ).scalars().first()
            if job is None:
                return None
            job.status = "leased"
            job.leased_at = _now()
            job.attempts += 1
            return {"id": job.id, "kind": job.kind, "payload": dict(job.payload),
                    "run_id": job.run_id, "attempts": job.attempts}

    def complete(self, job_id: int) -> None:
        with get_db().session() as s:
            job = s.get(m.Job, job_id)
            if job:
                job.status = "done"

    def fail(self, job_id: int, error: str) -> None:
        with get_db().session() as s:
            job = s.get(m.Job, job_id)
            if job:
                # Retry a couple of times before giving up.
                job.status = "queued" if job.attempts < 3 else "error"
                job.error = error[:500]

    def status(self, job_id: int) -> Optional[str]:
        with get_db().session() as s:
            job = s.get(m.Job, job_id)
            return job.status if job else None


def get_queue() -> JobQueue:
    if SETTINGS.queue_backend == "arq":
        try:
            from .arq_queue import ArqQueue

            return ArqQueue()
        except Exception:
            pass  # fall back to local if redis/arq unavailable
    return LocalQueue()
