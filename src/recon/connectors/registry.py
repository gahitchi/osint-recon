"""Connector registry: the catalogue of intel sources and their priors.

Reliability priors reflect how trustworthy a source's raw output is *before*
runtime history adjusts it. Deterministic/authoritative sources (offline phone
parsing, DNS/RDAP) rank high; fuzzy or scraped sources rank lower so they can't
outvote hard evidence during correlation.
"""

from __future__ import annotations

from ..collectors import domain, email, name, phone, username
from ..models import Query
from .base import Connector

REGISTRY: list[Connector] = [
    Connector("username", "username", username.collect, reliability_prior=0.75),
    Connector("email", "email", email.collect, reliability_prior=0.85),
    Connector("phone", "phone", phone.collect, reliability_prior=0.95),
    Connector("domain", "domain", domain.collect, reliability_prior=0.90),
    Connector("name", "name", name.collect, reliability_prior=0.60),
]


def get_registry() -> list[Connector]:
    return REGISTRY


def applicable_connectors(query: Query) -> list[Connector]:
    return [c for c in REGISTRY if c.applicable(query)]
