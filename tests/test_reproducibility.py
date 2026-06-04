"""Reproducibility: deterministic probe + provenance stamping (#8)."""

import dataclasses

from recon.config import SETTINGS
from recon.verify import baseline
from recon.provenance import provenance, sites_dataset_hash


def test_deterministic_probe_is_stable(monkeypatch):
    monkeypatch.setattr(baseline, "SETTINGS", dataclasses.replace(SETTINGS, deterministic=True))
    a = baseline.random_absent_account(key="GitHub")
    b = baseline.random_absent_account(key="GitHub")
    c = baseline.random_absent_account(key="GitLab")
    assert a == b           # same site -> same probe across runs
    assert a != c           # different site -> different probe
    assert a.startswith("zz")


def test_nondeterministic_probe_varies(monkeypatch):
    monkeypatch.setattr(baseline, "SETTINGS", dataclasses.replace(SETTINGS, deterministic=False))
    assert baseline.random_absent_account(key="X") != baseline.random_absent_account(key="X")


def test_provenance_has_versions_and_dataset_hash():
    p = provenance()
    assert p["tool_version"]
    assert p["sites_dataset_sha256"] == sites_dataset_hash()
    assert "httpx" in p["dependencies"]
    assert "baseline_similarity_reject" in p["thresholds"]
