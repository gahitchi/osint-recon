"""Evaluate declarative correlation rules against a run's discovery graph.

Pure and synchronous: it takes the artifacts + edges the recursive engine
already produced (`graph_models.Artifact`, `engine._Edge`) and returns
`RuleHit`s. No I/O, so it runs cheaply inside the persistence thread of
`orchestrator.scan()` and is trivial to unit-test.

The differentiator over a pile of hardcoded `if` checks: rules are *data*
(`rules/library.py` + an optional `RECON_RULES_FILE`), interpreted here. Adding
"same avatar across N accounts" or "reused handle + breached email" is a dict,
not a code change.
"""

from __future__ import annotations

from typing import Any, Iterable

from .. import normalize
from ..graph_models import Artifact
from .model import Clause, Rule, RuleHit

# --- field access + predicate evaluation -----------------------------------

_SCALAR_FIELDS = {"type", "value", "normalized", "depth", "source_module", "confidence"}


def _resolve(art: Artifact, path: str) -> Any:
    """Resolve a dotted field path against an artifact (``data.x`` reads data)."""
    if path == "type":
        return art.type.value
    if path in _SCALAR_FIELDS:
        return getattr(art, path)
    if path.startswith("data."):
        return art.data.get(path[5:])
    return None


def _match_pred(value: Any, spec: Any) -> bool:
    if not isinstance(spec, dict):
        return value == spec
    for op, operand in spec.items():
        if op == "eq" and value != operand:
            return False
        if op == "ne" and value == operand:
            return False
        if op == "in" and value not in operand:
            return False
        if op == "gte" and not (value is not None and value >= operand):
            return False
        if op == "lte" and not (value is not None and value <= operand):
            return False
        if op == "contains" and (value is None or operand not in value):
            return False
        if op == "present" and (value is None) == bool(operand):
            return False
        if op == "absent" and (value is None) != bool(operand):
            return False
    return True


def _clause_matches(art: Artifact, clause: Clause) -> bool:
    if art.type.value != clause.type:
        return False
    return all(_match_pred(_resolve(art, path), spec) for path, spec in clause.where.items())


# --- key derivers (for join / group_by / distinct) -------------------------

def _local_handle(email: str | None) -> str | None:
    if not email or "@" not in email:
        return normalize.fold_handle(email)
    return normalize.fold_handle(email.split("@", 1)[0])


def _handle_of(art: Artifact) -> str | None:
    t = art.type.value
    if t == "username":
        return normalize.fold_handle(art.value)
    if t == "email":
        return _local_handle(art.normalized or art.value)
    if t == "breach":
        return _local_handle(art.data.get("email"))
    if t in ("account_profile", "url", "link"):
        return normalize.fold_handle(normalize.norm_url(art.value).rsplit("/", 1)[-1])
    return None


def _platform_of(art: Artifact) -> str | None:
    host = normalize.norm_domain(art.value)
    return normalize.canonical_platform(host) if host else None


def _derive(name: str, art: Artifact) -> str | None:
    if name == "value":
        return art.normalized or art.value
    if name == "source":
        return art.source_module
    if name == "parent":
        return art.parent_key or art.key
    if name == "handle":
        return _handle_of(art)
    if name == "platform":
        return _platform_of(art)
    if name == "domain":
        v = art.normalized or art.value
        return v.rsplit("@", 1)[-1] if "@" in v else normalize.norm_domain(v)
    return None


def _evidence(arts: Iterable[Artifact], cap: int = 12) -> list[dict[str, Any]]:
    out = []
    for a in arts:
        out.append({"type": a.type.value, "value": a.value, "via": a.source_module})
        if len(out) >= cap:
            break
    return out


# --- per-kind evaluation ----------------------------------------------------

def _eval_threshold(rule: Rule, arts: list[Artifact]) -> list[RuleHit]:
    clause = rule.match[0]
    hits = [a for a in arts if _clause_matches(a, clause)]
    if len(hits) < rule.min_count:
        return []
    return [RuleHit(rule.id, rule.title, rule.severity.value, rule.description,
                    key=clause.type, evidence=_evidence(hits),
                    detail={"count": len(hits)})]


def _eval_co_occurrence(rule: Rule, arts: list[Artifact]) -> list[RuleHit]:
    matched = [[a for a in arts if _clause_matches(a, c)] for c in rule.match]
    if any(not group for group in matched):
        return []
    if not rule.join:  # mere co-presence
        flat = [a for group in matched for a in group]
        return [RuleHit(rule.id, rule.title, rule.severity.value, rule.description,
                        key="*", evidence=_evidence(flat), detail={})]
    # Tie clauses together by a shared derived key present in every clause.
    keyed = [{} for _ in matched]  # type: list[dict[str, list[Artifact]]]
    for i, group in enumerate(matched):
        for a in group:
            k = _derive(rule.join, a)
            if k:
                keyed[i].setdefault(k, []).append(a)
    common = set(keyed[0])
    for k in keyed[1:]:
        common &= set(k)
    out = []
    for key in sorted(common):
        ev = [a for grp in keyed for a in grp.get(key, [])]
        out.append(RuleHit(rule.id, rule.title, rule.severity.value, rule.description,
                           key=key, evidence=_evidence(ev), detail={"join": rule.join}))
    return out


def _eval_shared(rule: Rule, arts: list[Artifact],
                 parents_of: dict[str, set[str]]) -> list[RuleHit]:
    clause = rule.match[0]
    groups: dict[str, list[Artifact]] = {}
    for a in arts:
        if not _clause_matches(a, clause):
            continue
        gk = _derive(rule.group_by, a)
        if gk:
            groups.setdefault(gk, []).append(a)
    out = []
    for gk, members in groups.items():
        if rule.distinct == "parent":
            # Distinct *incoming* provenance — robust to artifact dedup, where one
            # shared node (e.g. an avatar hash) carries several parent edges.
            distinct: set[str] = set()
            for a in members:
                distinct |= parents_of.get(a.key, set())
        else:
            distinct = {d for d in (_derive(rule.distinct, a) for a in members) if d}
        if len(distinct) >= rule.min_distinct:
            out.append(RuleHit(rule.id, rule.title, rule.severity.value, rule.description,
                               key=gk, evidence=_evidence(members),
                               detail={"distinct_" + rule.distinct: len(distinct)}))
    return out


def _build_parents(artifacts: list[Artifact], edges: list | None) -> dict[str, set[str]]:
    """key -> set of parent keys, from each artifact's own provenance and from
    edges (edges win when artifacts are deduped to a single shared node)."""
    parents: dict[str, set[str]] = {}
    for a in artifacts:
        if a.parent_key:
            parents.setdefault(a.key, set()).add(a.parent_key)
    for e in edges or []:
        src = getattr(e, "src_key", None)
        dst = getattr(e, "dst_key", None)
        if src and dst:
            parents.setdefault(dst, set()).add(src)
    return parents


def evaluate(artifacts: list[Artifact], edges: list | None = None,
             rules: list[Rule] | None = None) -> list[RuleHit]:
    """Run every rule over the discovery graph and return fired hits, ordered
    most-severe first."""
    if rules is None:
        from .library import load_rules
        rules = load_rules()
    parents_of = _build_parents(artifacts, edges)
    hits: list[RuleHit] = []
    for rule in rules:
        if not rule.match:
            continue
        if rule.kind == "threshold":
            hits.extend(_eval_threshold(rule, artifacts))
        elif rule.kind == "co_occurrence":
            hits.extend(_eval_co_occurrence(rule, artifacts))
        elif rule.kind == "shared":
            hits.extend(_eval_shared(rule, artifacts, parents_of))
    hits.sort(key=lambda h: (-_sev_rank(h.severity), h.rule_id, h.key))
    return hits


def _sev_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3}.get(sev, 0)
