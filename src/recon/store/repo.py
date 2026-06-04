"""Typed repository helpers — the only place the rest of the app touches ORM.

All functions take an open Session so callers control the transaction boundary.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Finding, Query
from . import models_db as m


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --- Targets ---------------------------------------------------------------

def get_or_create_target(s: Session, query: Query, label: str | None = None,
                         watchlist: bool = False) -> m.Target:
    q = query.normalized().model_dump(exclude_none=True)
    existing = s.execute(
        select(m.Target).where(m.Target.query == q)
    ).scalars().first()
    if existing:
        if watchlist and not existing.watchlist:
            existing.watchlist = True
        return existing
    t = m.Target(label=label or _label_for(q), query=q, watchlist=watchlist)
    s.add(t)
    s.flush()
    return t


def _label_for(q: dict) -> str:
    for k in ("username", "name", "email", "domain", "phone"):
        if q.get(k):
            return str(q[k])
    return "target"


def list_targets(s: Session, watchlist_only: bool = False) -> list[m.Target]:
    stmt = select(m.Target).order_by(m.Target.created_at.desc())
    if watchlist_only:
        stmt = stmt.where(m.Target.watchlist.is_(True))
    return list(s.execute(stmt).scalars().all())


# --- Runs ------------------------------------------------------------------

def create_run(s: Session, target: m.Target) -> m.Run:
    r = m.Run(target_id=target.id, status="running")
    s.add(r)
    s.flush()
    return r


def finish_run(s: Session, run: m.Run, status: str, stats: dict) -> None:
    run.status = status
    run.finished_at = _now()
    run.stats = stats


def latest_finished_run(s: Session, target_id: int, before_run_id: int | None = None) -> Optional[m.Run]:
    stmt = (
        select(m.Run)
        .where(m.Run.target_id == target_id, m.Run.status == "done")
        .order_by(m.Run.started_at.desc())
    )
    if before_run_id is not None:
        stmt = stmt.where(m.Run.id < before_run_id)
    return s.execute(stmt).scalars().first()


def list_runs(s: Session, target_id: int | None = None, limit: int = 50) -> list[m.Run]:
    stmt = select(m.Run).order_by(m.Run.started_at.desc()).limit(limit)
    if target_id is not None:
        stmt = stmt.where(m.Run.target_id == target_id)
    return list(s.execute(stmt).scalars().all())


# --- Observations ----------------------------------------------------------

def add_observation(s: Session, run: m.Run, finding: Finding,
                    reliability: float = 0.5) -> m.Observation:
    obs = m.Observation(
        run_id=run.id,
        target_id=run.target_id,
        source=finding.source,
        category=finding.category,
        label=finding.label,
        url=finding.url,
        verdict=finding.verdict.value,
        confidence=finding.confidence,
        reasons=list(finding.reasons),
        signals=dict(finding.signals),
        data=dict(finding.data),
        fingerprint=str(finding.data.get("fingerprint") or "") or None,
        reliability=reliability,
    )
    s.add(obs)
    return obs


def observations_for_run(s: Session, run_id: int, hits_only: bool = False) -> list[m.Observation]:
    stmt = select(m.Observation).where(m.Observation.run_id == run_id)
    if hits_only:
        stmt = stmt.where(m.Observation.verdict.in_(["FOUND", "UNCERTAIN"]))
    return list(s.execute(stmt).scalars().all())


def observations_for_target(s: Session, target_id: int, hits_only: bool = True) -> list[m.Observation]:
    stmt = select(m.Observation).where(m.Observation.target_id == target_id)
    if hits_only:
        stmt = stmt.where(m.Observation.verdict.in_(["FOUND", "UNCERTAIN"]))
    return list(s.execute(stmt).scalars().all())


# --- Change events ---------------------------------------------------------

def add_change(s: Session, target_id: int, run_id: int, kind: str,
               source: str | None, label: str | None, detail: dict) -> m.ChangeEvent:
    ev = m.ChangeEvent(target_id=target_id, run_id=run_id, kind=kind,
                       source=source, label=label, detail=detail)
    s.add(ev)
    return ev


def list_changes(s: Session, target_id: int | None = None, limit: int = 100) -> list[m.ChangeEvent]:
    stmt = select(m.ChangeEvent).order_by(m.ChangeEvent.created_at.desc()).limit(limit)
    if target_id is not None:
        stmt = stmt.where(m.ChangeEvent.target_id == target_id)
    return list(s.execute(stmt).scalars().all())


# --- Schedules -------------------------------------------------------------

def create_schedule(s: Session, target_id: int, cron: str) -> m.Schedule:
    sc = m.Schedule(target_id=target_id, cron=cron, enabled=True)
    s.add(sc)
    s.flush()
    return sc


def list_schedules(s: Session, enabled_only: bool = True) -> list[m.Schedule]:
    stmt = select(m.Schedule)
    if enabled_only:
        stmt = stmt.where(m.Schedule.enabled.is_(True))
    return list(s.execute(stmt).scalars().all())


def touch_schedule(s: Session, schedule_id: int) -> None:
    sc = s.get(m.Schedule, schedule_id)
    if sc:
        sc.last_run_at = _now()


# --- Entities / graph (read helpers for API + reporting) -------------------

def list_entities(s: Session, target_id: int) -> list[m.Entity]:
    ent_ids = list(s.execute(
        select(m.Observation.entity_id).where(
            m.Observation.target_id == target_id,
            m.Observation.entity_id.is_not(None)).distinct()
    ).scalars().all())
    if not ent_ids:
        return []
    return list(s.execute(
        select(m.Entity).where(m.Entity.id.in_(ent_ids))
        .order_by(m.Entity.confidence.desc())
    ).scalars().all())


def list_sources(s: Session) -> list[m.Source]:
    return list(s.execute(select(m.Source).order_by(m.Source.name)).scalars().all())
