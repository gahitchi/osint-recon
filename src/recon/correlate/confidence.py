"""Confidence propagation for a resolved identity.

Confidence rises with independent corroboration (distinct sources) weighted by
each source's reliability, and falls when coherence flags contradictions.
Replaces the old heuristic correlate/score.py.
"""

from __future__ import annotations

from ..store import models_db as m


def entity_confidence(observations: list[m.Observation], flags: list[str]) -> float:
    hits = [o for o in observations if o.verdict in ("FOUND", "UNCERTAIN")]
    if not hits:
        return 0.0

    # Reliability-weighted average per-observation confidence.
    num = sum(o.confidence * (o.reliability or 0.5) for o in hits)
    den = sum(o.reliability or 0.5 for o in hits)
    base = num / den if den else 0.0

    # Breadth bonus: independent distinct sources corroborating.
    distinct = len({o.source for o in hits if o.verdict == "FOUND"})
    breadth = min(0.25, 0.08 * max(0, distinct - 1))

    penalty = 0.15 * len(flags)

    return round(max(0.0, min(1.0, base + breadth - penalty)), 3)
