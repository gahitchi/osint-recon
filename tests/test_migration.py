"""The SQLite column-backfill: an older DB created before a column was added
(e.g. observations.breakdown) gains it on create_all, without data loss."""

import sqlalchemy as sa

from recon.store.db import Database

_OLD_OBSERVATIONS = """
CREATE TABLE observations (
  id INTEGER PRIMARY KEY, run_id INTEGER, target_id INTEGER, entity_id INTEGER,
  source TEXT, category TEXT, label TEXT, url TEXT, verdict TEXT,
  confidence FLOAT, reasons JSON, signals JSON, data JSON,
  fingerprint TEXT, reliability FLOAT, created_at DATETIME
)
"""


def test_backfill_adds_missing_column_preserving_rows(tmp_path):
    dsn = f"sqlite:///{tmp_path / 'old.db'}"
    eng = sa.create_engine(dsn)
    with eng.begin() as c:
        c.execute(sa.text(_OLD_OBSERVATIONS))            # pre-breakdown schema
        c.execute(sa.text("INSERT INTO observations (id, source, verdict, confidence) "
                          "VALUES (1, 'username:GitHub', 'FOUND', 0.9)"))
    eng.dispose()

    db = Database(dsn)
    db.create_all()                                       # should ALTER in 'breakdown'

    insp = sa.inspect(db.engine)
    cols = {c["name"] for c in insp.get_columns("observations")}
    assert "breakdown" in cols
    # Existing row survives the migration.
    with db.session() as s:
        row = s.execute(sa.text("SELECT source, breakdown FROM observations WHERE id=1")).one()
        assert row[0] == "username:GitHub"
        assert row[1] is None
