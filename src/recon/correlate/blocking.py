"""Blocking: generate candidate pairs cheaply so resolution scales.

Instead of comparing every record to every other (O(n^2)), we bucket records by
shared blocking keys and only compare within buckets — near-linear for large N.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .resolver import Record


def blocking_keys(rec: Record) -> set[str]:
    keys: set[str] = set()
    for v in rec.emails:
        keys.add(f"email:{v}")
        if "@" in v:
            keys.add(f"emaildom:{v.split('@', 1)[1]}")
    for key, vals in rec.strong.items():
        for v in vals:
            keys.add(f"{key}:{v}")
    for u in rec.usernames:
        keys.add(f"user:{u}")
    for n in rec.names:
        for tok in n.split():
            if len(tok) > 2:
                keys.add(f"name:{tok}")
    return keys


def candidate_pairs(records: list[Record]) -> set[tuple[int, int]]:
    """Indices (i, j) of records that share at least one blocking key."""
    buckets: dict[str, list[int]] = defaultdict(list)
    for i, rec in enumerate(records):
        for k in blocking_keys(rec):
            buckets[k].append(i)

    pairs: set[tuple[int, int]] = set()
    for members in buckets.values():
        if len(members) < 2:
            continue
        for i, j in combinations(sorted(set(members)), 2):
            pairs.add((i, j))
    return pairs
