"""Connector framework: a uniform, resilient wrapper around every intel source.

Adds, on top of the raw collectors, the things a professional tool needs:
result caching (so re-runs don't depend on live APIs), circuit breakers
(a dead source can't stall an investigation), and per-source reliability that
feeds correlation confidence.
"""

from .base import Connector  # noqa: F401
from .registry import REGISTRY, applicable_connectors, get_registry  # noqa: F401
