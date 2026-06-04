"""Test fixtures: isolate every test with its own fresh SQLite database."""

import pytest

from recon.store import db as db_mod


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    dsn = f"sqlite:///{tmp_path/'test.db'}"
    monkeypatch.setenv("RECON_DB_DSN", dsn)
    database = db_mod.init_db(dsn)  # creates tables, sets global
    yield database
    db_mod._DB = None
