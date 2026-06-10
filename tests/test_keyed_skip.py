"""Keyed modules are invisible without their vault key, and enabled with it."""

import pytest

from recon.engine import GraphScanEngine
from recon.models import Query
from recon.modules import abuseipdb, shodan, virustotal


@pytest.fixture
def engine():
    return GraphScanEngine(Query(domain="example.com"))


def test_keyed_modules_skipped_without_keys(engine, monkeypatch):
    # Ensure no key leaks in from the environment.
    for var in ("RECON_KEY_SHODAN", "RECON_KEY_VIRUSTOTAL", "RECON_KEY_ABUSEIPDB"):
        monkeypatch.delenv(var, raising=False)
    assert engine._module_enabled(shodan.MODULE) is False
    assert engine._module_enabled(virustotal.MODULE) is False
    assert engine._module_enabled(abuseipdb.MODULE) is False


def test_keyed_module_enabled_with_key(engine, monkeypatch):
    monkeypatch.setenv("RECON_KEY_SHODAN", "deadbeef")
    assert engine._module_enabled(shodan.MODULE) is True
    # The others remain gated by their own keys.
    monkeypatch.delenv("RECON_KEY_VIRUSTOTAL", raising=False)
    assert engine._module_enabled(virustotal.MODULE) is False


def test_keyless_module_always_enabled(engine):
    from recon.modules import ripestat
    assert engine._module_enabled(ripestat.MODULE) is True
