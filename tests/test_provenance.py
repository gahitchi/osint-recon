"""Phase-5b provenance/traceability: a per-finding trace is reproducible and
captures its inputs; run-level provenance reflects the settings used and is
served + persisted."""

import dataclasses

from fastapi.testclient import TestClient

from recon.config import SETTINGS
from recon.models import Evidence, Finding, Query, SiteRule, Verdict
from recon.provenance import finding_trace, provenance
from recon.server import app
from recon.store import get_db, repo

client = TestClient(app)


def _ev(status, fp, final="https://x/u", elapsed=0):
    return Evidence(url="https://x/u", status=status, final_url=final,
                    body_len=10, fingerprint=fp, elapsed_ms=elapsed)


def test_finding_trace_is_reproducible_and_captures_inputs():
    rule = SiteRule(name="GitHub", uri_check="https://github.com/{account}",
                    error_type="status_code", error_code=404)
    ev = _ev(200, "aaaa1111", elapsed=42)
    base = _ev(404, "bbbb2222", final="https://x/zzabsent")
    det = dataclasses.replace(SETTINGS, deterministic=True)

    t1 = finding_trace(module="username", source="username:GitHub",
                       rule=rule, ev=ev, baseline=base, settings=det)
    t2 = finding_trace(module="username", source="username:GitHub",
                       rule=rule, ev=ev, baseline=base, settings=det)
    assert t1 == t2                                    # no wall-clock -> reproducible
    assert t1["site_rule"]["name"] == "GitHub"
    assert t1["request"]["status"] == 200 and t1["request"]["elapsed_ms"] == 42
    assert t1["baseline"]["status"] == 404
    assert t1["deterministic"] is True
    assert "dataset_sha256" in t1 and "found_confidence" in t1["thresholds"]


def test_finding_trace_without_baseline():
    t = finding_trace(module="username", source="username:S")
    assert t["baseline"] is None and t["module"] == "username"


def test_provenance_reflects_settings():
    flipped = dataclasses.replace(SETTINGS, confidence_independence=True,
                                  scope_mode="aggressive", deterministic=True)
    p = provenance(flipped)
    assert p["engine"]["confidence_independence"] is True
    assert p["engine"]["scope_mode"] == "aggressive"
    assert p["deterministic"] is True and p["probe_seed"] == flipped.probe_seed
    assert "found_confidence" in p["thresholds"]
    assert p["tool_version"] == provenance(SETTINGS)["tool_version"]


def test_run_provenance_endpoint_and_trace_persist():
    db = get_db()
    db.create_all()
    with db.session() as s:
        target = repo.get_or_create_target(s, Query(username="x"))
        run = repo.create_run(s, target)
        run.provenance = provenance(SETTINGS)
        f = Finding(source="username:GitHub", category="username", label="GitHub",
                    verdict=Verdict.FOUND, confidence=0.9,
                    trace={"module": "username", "dataset_sha256": "deadbeef"})
        repo.add_observation(s, run, f, reliability=0.7)
        run_id = run.id

    body = client.get(f"/api/runs/{run_id}/provenance").json()
    assert body["run_id"] == run_id
    assert body["provenance"]["tool_version"]
    assert body["provenance"]["engine"]["scope_mode"] in ("strict", "aggressive")

    assert client.get("/api/runs/99999999/provenance").status_code == 404

    with db.session() as s:
        obs = repo.observations_for_run(s, run_id)
        assert obs and obs[0].trace["module"] == "username"
