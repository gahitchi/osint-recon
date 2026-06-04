"""Database engine + session management.

Local-first default is a SQLite file; set RECON_DB_DSN (or config.storage_dsn)
to a Postgres URL for scale-out. One SQLAlchemy layer covers both.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import SETTINGS
from .models_db import Base


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        connect_args = {"check_same_thread": False} if dsn.startswith("sqlite") else {}
        self.engine: Engine = create_engine(dsn, future=True, connect_args=connect_args)
        self._Session = sessionmaker(self.engine, expire_on_commit=False, future=True)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

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
    _DB = Database(dsn or _default_dsn())
    _DB.create_all()
    return _DB
