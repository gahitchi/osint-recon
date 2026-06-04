"""Cron-like scheduler for recurring re-scans (long-term monitoring).

Each enabled Schedule row maps to an APScheduler cron job that enqueues a durable
scan for its target. Decoupling 'decide to scan' (scheduler) from 'do the scan'
(worker) means monitoring scales the same way ad-hoc scans do.
"""

from __future__ import annotations

from ..jobs import get_queue
from ..store import get_db
from ..store import models_db as m
from ..store import repo


def enqueue_scan_for_target(target_id: int) -> int:
    """Queue a scan for a target using its stored query. Returns the job id."""
    db = get_db()
    with db.session() as s:
        target = s.get(m.Target, target_id)
        query = dict(target.query) if target else {}
    return get_queue().enqueue("scan", {"query": query, "watchlist": True})


class MonitorScheduler:
    def __init__(self) -> None:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        self.sched = AsyncIOScheduler()

    def load(self) -> int:
        from apscheduler.triggers.cron import CronTrigger

        db = get_db()
        count = 0
        with db.session() as s:
            for sc in repo.list_schedules(s, enabled_only=True):
                self.sched.add_job(
                    self._fire, CronTrigger.from_crontab(sc.cron),
                    args=[sc.id, sc.target_id], id=f"sched-{sc.id}",
                    replace_existing=True,
                )
                count += 1
        return count

    async def _fire(self, schedule_id: int, target_id: int) -> None:
        enqueue_scan_for_target(target_id)
        db = get_db()
        with db.session() as s:
            repo.touch_schedule(s, schedule_id)

    def start(self) -> None:
        self.load()
        self.sched.start()

    def shutdown(self) -> None:
        self.sched.shutdown(wait=False)


def validate_cron(expr: str) -> bool:
    """True if `expr` is a valid 5-field crontab string."""
    try:
        from apscheduler.triggers.cron import CronTrigger

        CronTrigger.from_crontab(expr)
        return True
    except Exception:
        return False
