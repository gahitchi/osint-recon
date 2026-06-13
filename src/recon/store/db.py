"""Database engine + session management.

Local-first default is a SQLite file; set RECON_DB_DSN (or config.storage_dsn)
to a Postgres URL for scale-out. One SQLAlchemy layer covers both.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import SETTINGS
from .models_db import Base


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        connect_args = {"check_same_thread": False} if dsn.startswith("sqlite") else {}
        self.engine: Engine = create_engine(dsn, future=True, connect_args=connect_args)
        if dsn.startswith("sqlite"):
            self._enable_sqlite_concurrency(self.engine)
        self._Session = sessionmaker(self.engine, expire_on_commit=False, future=True)

    @staticmethod
    def _enable_sqlite_concurrency(engine: Engine) -> None:
        """The recursive engine runs modules concurrently, each doing a little
        reliability bookkeeping. On the default SQLite file that means concurrent
        writers; without these pragmas a writer can hit 'database is locked' and a
        module silently fails to run. WAL lets readers and a writer coexist, and
        busy_timeout makes a contending writer wait rather than error."""
        @event.listens_for(engine, "connect")
        def _set_pragmas(dbapi_conn, _record):  # pragma: no cover - driver callback
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)
        if self.engine.dialect.name == "sqlite":
            self._backfill_columns()

    def _backfill_columns(self) -> None:
        """Add any nullable columns introduced after a table was first created.

        SQLAlchemy's create_all never ALTERs existing tables, so a schema change
        like `observations.breakdown` would otherwise break older local DBs. This
        is a lightweight, data-preserving migration for the SQLite default (no
        Alembic dependency); Postgres deployments should use real migrations."""
        insp = inspect(self.engine)
        tables = set(insp.get_table_names())
        with self.engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if table.name not in tables:
                    continue
                have = {c["name"] for c in insp.get_columns(table.name)}
                for col in table.columns:
                    if col.name in have:
                        continue
                    if not col.nullable and col.default is None and col.server_default is None:
                        continue  # can't safely add NOT NULL to populated rows
                    coltype = col.type.compile(self.engine.dialect)
                    conn.execute(text(
                        f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}'))

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def close(self) -> None:
        """Dispose the engine's connection pool, closing pooled DBAPI handles.

        Without this, an abandoned Database leaks its SQLite connections until
        the interpreter's GC reclaims them (surfacing as ResourceWarning under
        warnings-as-errors). Idempotent and safe to call more than once."""
        self.engine.dispose()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _default_dsn() -> str:
    dsn = os.environ.get("RECON_DB_DSN") or SETTINGS.storage_dsn
    if dsn.startswith("sqlite") and ":memory:" not in dsn:
        # Ensure parent dir exists for file-based sqlite.
        path = dsn.split("///", 1)[-1]
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    return dsn


_DB: Optional[Database] = None


def get_db() -> Database:
    global _DB
    if _DB is None:
        _DB = Database(_default_dsn())
        _DB.create_all()  # idempotent; guarantees tables exist for any caller
    return _DB


def init_db(dsn: str | None = None) -> Database:
    """(Re)initialize the global database and create tables. Used by CLI/tests."""
    global _DB
    if _DB is not None:
        _DB.close()  # release the previous engine's pooled connections
    _DB = Database(dsn or _default_dsn())
    _DB.create_all()
    return _DB
