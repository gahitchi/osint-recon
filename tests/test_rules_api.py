"""Phase-4 web API: persisted rule findings per run + the rule catalogue."""

from fastapi.testclient import TestClient

from recon.graph_models import Artifact, ArtifactType as AT
from recon.models import Query
from recon.rules import evaluate, load_rules
from recon.server import app
from recon.store import get_db, repo

client = TestClient(app)


def test_rule_catalogue_endpoint():
    cat = {r["id"]: r for r in client.get("/api/rules").json()}
    assert "handle-reuse-breached" in cat
    assert cat["handle-reuse-breached"]["severity"] == "high"
    assert cat["handle-reuse-breached"]["kind"] == "co_occurrence"


def test_run_rules_endpoint_returns_persisted_insights():
    db = get_db()
    db.create_all()
    with db.session() as s:
        target = repo.get_or_create_target(s, Query(username="torvalds"))
        run = repo.create_run(s, target)
        user = Artifact.make(AT.USERNAME, "torvalds")
        email = Artifact.make(AT.EMAIL, "torvalds@example.com")
        breach = Artifact.make(AT.BREACH, "AcmeLeak", parent=email,
                               source_module="breach", email="torvalds@example.com")
        hits = evaluate([user, email, breach], rules=load_rules())
        repo.persist_rule_findings(s, run, hits)
        run_id = run.id

    body = client.get(f"/api/runs/{run_id}/rules").json()
    assert body["run_id"] == run_id
    ids = {i["rule_id"] for i in body["insights"]}
    assert {"email-in-breach", "handle-reuse-breached"} <= ids
    # Most-severe first.
    assert body["insights"][0]["severity"] == "high"
    # Evidence travels with the finding.
    hr = next(i for i in body["insights"] if i["rule_id"] == "handle-reuse-breached")
    assert any(e["type"] == "breach" for e in hr["evidence"])


def test_run_with_no_insights_is_empty():
    db = get_db()
    db.create_all()
    with db.session() as s:
        target = repo.get_or_create_target(s, Query(domain="quiet.example"))
        run = repo.create_run(s, target)
        run_id = run.id
    body = client.get(f"/api/runs/{run_id}/rules").json()
    assert body["insights"] == []
