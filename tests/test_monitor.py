"""Scheduler: schedules enqueue durable scans; cron validation."""

from recon.models import Query
from recon.monitor.scheduler import enqueue_scan_for_target, validate_cron
from recon.jobs.base import LocalQueue
from recon.store import get_db, repo


def test_validate_cron():
    assert validate_cron("0 */6 * * *")
    assert not validate_cron("not a cron")


def test_schedule_enqueues_scan_for_target_query():
    db = get_db()
    with db.session() as s:
        t = repo.get_or_create_target(s, Query(username="alice", email="a@x.com"),
                                      watchlist=True)
        tid = t.id
        repo.create_schedule(s, tid, "0 0 * * *")

    job_id = enqueue_scan_for_target(tid)
    q = LocalQueue()
    assert q.status(job_id) == "queued"

    leased = q.lease()
    assert leased["payload"]["query"]["username"] == "alice"
    assert leased["payload"]["query"]["email"] == "a@x.com"
