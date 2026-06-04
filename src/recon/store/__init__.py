"""Persistence layer: durable storage backing investigations, monitoring, and
correlation. SQLite by default (local-first); switch the DSN to Postgres for
scale-out without code changes.
"""

from .db import Database, get_db, init_db  # noqa: F401
from . import repo  # noqa: F401
