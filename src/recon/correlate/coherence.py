"""Coherence checks: surface contradictions inside a resolved identity.

The identity-graph analogue of the FP engine's reasons[] — an over-merged or
inconsistent cluster gets flagged (and penalized) rather than trusted blindly.
"""

from __future__ import annotations

import jellyfish

from ..config import SETTINGS
from .resolver import STRONG, Record


def check(records: list[Record]) -> list[str]:
    flags: list[str] = []

    # Multiple distinct values of the same strong identifier -> conflict.
    for key in STRONG:
        vals = set()
        for r in records:
            vals |= r.strong.get(key, set())
        if len(vals) > 1:
            flags.append(f"identifier-conflict:{key}")

    # Names that disagree strongly within one identity.
    names = sorted({n for r in records for n in r.names})
    if len(names) > 1:
        worst = min(
            jellyfish.jaro_winkler_similarity(a, b)
            for i, a in enumerate(names) for b in names[i + 1:]
        )
        if worst < 0.7:
            flags.append("name-conflict")

    return flags
