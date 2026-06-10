"""Module registry: the catalogue the engine dispatches against.

Mirrors `connectors/registry.py`. Reliability priors reflect how trustworthy a
module's raw output is before runtime history adjusts it: deterministic/
authoritative sources (DNS resolution, Team Cymru ASN) rank high; scraped
sources (profile-link harvesting) rank low so they can't outvote hard evidence
during correlation."""

from __future__ import annotations

from ..graph_models import Artifact
from . import (
    abuseipdb,
    asn,
    breach,
    commoncrawl,
    dns_intel,
    domain,
    email,
    github,
    ip_geo,
    name,
    phone,
    profile_links,
    resolve,
    ripestat,
    shodan,
    username,
    virustotal,
    wayback,
)
from .base import Module

MODULES: list[Module] = [
    # Phase 1 — core collectors + recursive engine
    username.MODULE,
    email.MODULE,
    phone.MODULE,
    name.MODULE,
    domain.MODULE,
    resolve.MODULE,
    asn.MODULE,
    profile_links.MODULE,
    wayback.MODULE,
    # Phase 2 — network/infra (keyless)
    ripestat.MODULE,
    ip_geo.MODULE,
    dns_intel.MODULE,
    commoncrawl.MODULE,
    # Phase 2 — identity pivots (keyless)
    github.MODULE,
    breach.MODULE,
    # Phase 2 — keyed, optional (auto-skipped without vault keys)
    shodan.MODULE,
    virustotal.MODULE,
    abuseipdb.MODULE,
]


def get_modules() -> list[Module]:
    return MODULES


def applicable_modules(art: Artifact) -> list[Module]:
    return [m for m in MODULES if m.accepts(art)]
