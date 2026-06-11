"""Declarative correlation-rule model.

A rule is *data*, not code: it names a graph pattern over the discovery
artifacts (see `graph_models.Artifact`) and a severity. The evaluator
(`rules/engine.py`) interprets these uniformly, so new insights can be added —
by users, via `RECON_RULES_FILE` — without touching Python.

Three rule *kinds* cover the patterns that matter for OSINT correlation:

- ``threshold``     — at least N artifacts match a single clause
                      (e.g. "email exposed in a breach", "broad subdomain footprint").
- ``co_occurrence`` — every clause has a match, optionally tied together by a
                      shared *join* key derived from each artifact
                      (e.g. "reused handle + breached email": a USERNAME and a
                      BREACH that fold to the same handle).
- ``shared``        — one artifact type, grouped by a derived key, where a group
                      spans ≥N *distinct* parents/sources/platforms
                      (e.g. "same avatar hash across N accounts").
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


@dataclass(frozen=True)
class Clause:
    """Selects artifacts of one type, optionally filtered by a field predicate.

    `where` maps a dotted field path (``type``/``value``/``normalized``/``depth``/
    ``source_module``/``confidence`` or ``data.<key>``) to either a literal
    (equality) or an ``{op: operand}`` spec. Ops: ``eq, ne, in, gte, lte,
    contains, present, absent``."""

    type: str
    where: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    kind: str                                  # threshold | co_occurrence | shared
    match: tuple[Clause, ...] = ()
    join: str | None = None                    # co_occurrence: key deriver tying clauses
    group_by: str = "value"                    # shared: key deriver to group on
    distinct: str = "parent"                   # shared: what must differ within a group
    min_count: int = 1                         # threshold
    min_distinct: int = 2                      # shared: distinct members to fire

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        clauses = tuple(
            Clause(type=str(c["type"]), where=dict(c.get("where", {})))
            for c in d.get("match", [])
        )
        return cls(
            id=str(d["id"]),
            title=str(d.get("title", d["id"])),
            severity=Severity(str(d.get("severity", "info")).lower()),
            description=str(d.get("description", "")),
            kind=str(d["kind"]),
            match=clauses,
            join=d.get("join"),
            group_by=str(d.get("group_by", "value")),
            distinct=str(d.get("distinct", "parent")),
            min_count=int(d.get("min_count", 1)),
            min_distinct=int(d.get("min_distinct", 2)),
        )


@dataclass
class RuleHit:
    """A fired rule: which rule, the key it fired on, and the artifacts that
    constitute the evidence (kept small for storage/display)."""

    rule_id: str
    title: str
    severity: str
    description: str
    key: str
    evidence: list[dict[str, Any]]
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "description": self.description, "key": self.key,
            "evidence": self.evidence, "detail": self.detail,
        }
