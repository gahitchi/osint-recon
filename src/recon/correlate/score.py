"""Corroboration scoring for identity clusters.

An identity backed by several independent FOUND sources and strong shared
signals is more trustworthy than a single weak hit. This score is reported
alongside per-finding verdicts (it does not override them).
"""

from __future__ import annotations

from ..models import Verdict
from .cluster import Identity


def score_identity(identity: Identity) -> float:
    found = [f for f in identity.findings if f.verdict == Verdict.FOUND]
    uncertain = [f for f in identity.findings if f.verdict == Verdict.UNCERTAIN]
    if not found and not uncertain:
        return 0.0

    # Distinct sources corroborating, weighted by per-finding confidence.
    distinct_sources = {f.source for f in found}
    base = sum(f.confidence for f in found) + 0.3 * sum(f.confidence for f in uncertain)
    # Bonus for breadth (independent corroboration) and for strong shared signals.
    breadth = min(0.3, 0.1 * (len(distinct_sources) - 1)) if distinct_sources else 0.0
    strong_signal_bonus = min(0.2, 0.1 * len(identity.signals))

    raw = base / (len(found) + len(uncertain)) if (found or uncertain) else 0.0
    return round(min(1.0, raw + breadth + strong_signal_bonus), 3)


def summarize(identities: list[Identity]) -> dict:
    return {
        "identities": len(identities),
        "clusters": [
            {
                "id": idn.id,
                "score": score_identity(idn),
                "signals": {k: sorted(v) for k, v in idn.signals.items()},
                "found": sum(1 for f in idn.findings if f.verdict == Verdict.FOUND),
                "uncertain": sum(1 for f in idn.findings if f.verdict == Verdict.UNCERTAIN),
            }
            for idn in sorted(identities, key=lambda i: -score_identity(i))
        ],
    }
