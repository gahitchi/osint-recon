"""Identity graph construction over the Store.

correlate_run() rebuilds the target's identity clusters from all its accumulated
observations: blocking -> probabilistic scoring -> union-find merge of MERGE
pairs, REVIEW pairs recorded as edges (never silently merged). Persists Entity
nodes, links observations, and computes coherence flags + confidence.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import delete, select

from ..store import models_db as m
from ..store import repo
from . import coherence, confidence
from .blocking import candidate_pairs
from .cluster import _UF
from .resolver import Record, classify, record_from, score


def _merge_attributes(records: list[Record]) -> dict:
    emails, usernames, names = set(), set(), set()
    strong: dict[str, set] = defaultdict(set)
    for r in records:
        emails |= r.emails
        usernames |= r.usernames
        names |= r.names
        for k, vs in r.strong.items():
            strong[k] |= vs
    attrs: dict[str, list] = {}
    if emails:
        attrs["email"] = sorted(emails)
    if usernames:
        attrs["username"] = sorted(usernames)
    if names:
        attrs["name"] = sorted(names)
    for k, vs in strong.items():
        if k != "email":
            attrs[k] = sorted(vs)
    return attrs


def _label(attrs: dict) -> str:
    for k in ("name", "email", "username", "domain"):
        if attrs.get(k):
            return str(attrs[k][0])
    return "identity"


def _resolve_conflicts(records: list, observations: list) -> dict:
    """Conflict resolution (#3): when one strong identifier has multiple values in
    a cluster, pick the canonical one from the highest-reliability, then
    highest-confidence, observation that asserts it. Returns {attr: canonical}.
    """
    from .resolver import STRONG

    # value -> best (reliability, confidence) seen among observations asserting it
    best: dict[str, dict[str, tuple[float, float]]] = {}
    for o in observations:
        rel = o.reliability or 0.5
        for k, v in (o.signals or {}).items():
            base = k.split(":", 1)[0]
            if base not in STRONG or not v:
                continue
            vv = v.lower()
            cur = best.setdefault(base, {}).get(vv, (-1.0, -1.0))
            best[base][vv] = max(cur, (rel, o.confidence))

    canonical: dict[str, str] = {}
    for attr, values in best.items():
        if len(values) > 1:  # only meaningful when there's a conflict
            canonical[attr] = max(values.items(), key=lambda kv: kv[1])[0]
    return canonical


def correlate_run(db, run_id: int) -> dict:
    with db.session() as s:
        run = s.get(m.Run, run_id)
        target_id = run.target_id
        obs = repo.observations_for_target(s, target_id, hits_only=True)

        records = [record_from(o.id, o.category, o.label, o.signals) for o in obs]
        obs_by_oid = {o.id: o for o in obs}

        # --- clear prior correlation for this target (rebuild is deterministic) ---
        old_ids = list(s.execute(
            select(m.Observation.entity_id)
            .where(m.Observation.target_id == target_id,
                   m.Observation.entity_id.is_not(None))
            .distinct()
        ).scalars().all())
        if old_ids:
            s.execute(delete(m.EntityEdge).where(
                m.EntityEdge.src_id.in_(old_ids) | m.EntityEdge.dst_id.in_(old_ids)))
            s.execute(delete(m.Entity).where(m.Entity.id.in_(old_ids)))
            for o in obs:
                o.entity_id = None

        # --- score candidate pairs, merge / mark for review ---
        uf = _UF()
        for i in range(len(records)):
            uf.find(str(i))
        review: list[tuple[int, int, float, list[str]]] = []
        for i, j in candidate_pairs(records):
            w, reasons = score(records[i], records[j])
            decision = classify(w)
            if decision == "MERGE":
                uf.union(str(i), str(j))
            elif decision == "REVIEW":
                review.append((i, j, w, reasons))

        clusters: dict[str, list[int]] = defaultdict(list)
        for i in range(len(records)):
            clusters[uf.find(str(i))].append(i)

        # --- persist entities ---
        idx_to_entity: dict[int, int] = {}
        summary_clusters = []
        for idxs in clusters.values():
            recs = [records[k] for k in idxs]
            cl_obs = [obs_by_oid[records[k].obs_id] for k in idxs]
            flags = coherence.check(recs)
            attrs = _merge_attributes(recs)
            canonical = _resolve_conflicts(recs, cl_obs)
            if canonical:
                attrs["_canonical"] = canonical  # winning value per conflicted id
            bd = confidence.entity_confidence(cl_obs, flags)
            conf = bd.total
            ent = m.Entity(label=_label(attrs), attributes=attrs, confidence=conf,
                           breakdown=bd.model_dump(), flags=flags)
            s.add(ent)
            s.flush()
            for k in idxs:
                idx_to_entity[k] = ent.id
                obs_by_oid[records[k].obs_id].entity_id = ent.id
            summary_clusters.append({
                "id": ent.id,
                "label": ent.label,
                "score": conf,
                "confidence_shadow": bd.shadow_total,
                "breakdown": bd.model_dump(),
                "signals": attrs,
                "flags": flags,
                "found": sum(1 for o in cl_obs if o.verdict == "FOUND"),
                "uncertain": sum(1 for o in cl_obs if o.verdict == "UNCERTAIN"),
                "sources": sorted({o.source for o in cl_obs}),
            })

        # --- REVIEW edges between the resulting (distinct) entities ---
        for i, j, w, reasons in review:
            ei, ej = idx_to_entity[i], idx_to_entity[j]
            if ei != ej:
                s.add(m.EntityEdge(src_id=ei, dst_id=ej, kind="review", weight=w,
                                   detail={"reasons": reasons}))

        summary_clusters.sort(key=lambda c: -c["score"])
        return {"identities": len(summary_clusters), "clusters": summary_clusters}
