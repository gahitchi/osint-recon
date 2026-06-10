"""The event-driven recursive scan engine.

A scan is a breadth-first graph traversal. Seed identifiers become depth-0
artifacts; each artifact is dispatched to every module that consumes its type;
modules emit findings (streamed live) and new artifacts (pivots) that are
deduped, scope-checked, and budget-checked before being fed back into the
frontier. This is the capability that turns single-pass collection into the
recursive, self-pivoting traversal that defines tools like SpiderFoot — kept
honest here by hard depth/artifact/request ceilings and a scope policy.

The engine yields the SAME event-dict contract the old `run_stream` did
(`{"type": "finding"|"summary"|"done"|"error", ...}`), so the CLI, SSE server,
and `scan()` persistence path need no signature changes. Discovered artifacts
and the edges between them are exposed on the instance (`.artifacts`, `.edges`)
for persistence and graph inspection.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from .config import SETTINGS, Settings
from .correlate import score
from .correlate.cluster import cluster
from .graph_models import Artifact, ArtifactType
from .http_client import RateLimitedClient
from .keys import VAULT
from .models import Finding, Query
from .modules.base import ModuleContext
from .modules.registry import applicable_modules

# Artifact types that descend from an in-scope parent and are always safe to
# expand in strict mode (they can't broaden the investigation's subject).
_DESCENDANT_TYPES = {
    ArtifactType.IP_ADDRESS, ArtifactType.ASN, ArtifactType.NETBLOCK,
    ArtifactType.HASH, ArtifactType.BREACH, ArtifactType.ACCOUNT_PROFILE,
    ArtifactType.URL,
}
_HOST_TYPES = {
    ArtifactType.SUBDOMAIN, ArtifactType.HOSTNAME,
    ArtifactType.MX_HOST, ArtifactType.NAMESERVER,
}


@dataclass
class ScopePolicy:
    """Decides whether a newly discovered artifact may be *expanded* (have
    modules run on it). Out-of-scope artifacts are still recorded as graph nodes
    — they just don't broaden the traversal. Seeds are always in scope."""

    mode: str
    seed_domains: set[str] = field(default_factory=set)
    seed_handles: set[str] = field(default_factory=set)

    @classmethod
    def from_query(cls, query: Query, mode: str) -> "ScopePolicy":
        from .normalize import fold_handle, norm_domain

        domains: set[str] = set()
        if query.domain:
            domains.add(query.domain)
        if query.email and "@" in query.email:
            d = norm_domain(query.email.rsplit("@", 1)[-1])
            if d:
                domains.add(d)
        handles: set[str] = set()
        if query.username:
            h = fold_handle(query.username)
            if h:
                handles.add(h)
        if query.email and "@" in query.email:
            h = fold_handle(query.email.split("@", 1)[0])
            if h:
                handles.add(h)
        return cls(mode=mode, seed_domains=domains, seed_handles=handles)

    def in_scope(self, art: Artifact) -> bool:
        if self.mode == "aggressive":
            return True
        t = art.type
        if t in _DESCENDANT_TYPES:
            return True
        if t in _HOST_TYPES or t == ArtifactType.DOMAIN:
            return any(art.normalized == d or art.normalized.endswith("." + d)
                       for d in self.seed_domains)
        if t == ArtifactType.USERNAME:
            from .normalize import fold_handle
            folded = fold_handle(art.normalized)
            return bool(folded and folded in self.seed_handles)
        if t == ArtifactType.EMAIL:
            dom = art.normalized.rsplit("@", 1)[-1] if "@" in art.normalized else ""
            return dom in self.seed_domains
        # NAME / PHONE / LINK discovered mid-traversal: record, don't expand.
        return False


@dataclass
class _Edge:
    src_key: str
    dst_key: str
    module: str
    detail: dict


class GraphScanEngine:
    def __init__(self, query: Query, settings: Settings = SETTINGS) -> None:
        self.query = query.normalized()
        self.settings = settings
        self.scope = ScopePolicy.from_query(self.query, settings.scope_mode)
        # Results exposed for persistence / inspection.
        self.artifacts: list[Artifact] = []
        self.edges: list[_Edge] = []
        self.stop_reason: Optional[str] = None
        # Traversal state.
        self._seen: set[str] = set()
        self._requests = 0

    def _admit_node(self, art: Artifact) -> bool:
        """Record an artifact as a graph node (deduped, budgeted). Returns True
        if it is newly admitted."""
        if art.key in self._seen:
            return False
        if len(self._seen) >= self.settings.max_artifacts:
            self.stop_reason = self.stop_reason or "max_artifacts reached"
            return False
        self._seen.add(art.key)
        self.artifacts.append(art)
        return True

    def _should_expand(self, art: Artifact) -> bool:
        if art.depth > self.settings.max_depth:
            return False
        return self.scope.in_scope(art)

    def _module_enabled(self, mod) -> bool:
        if self.settings.passive_only and not mod.passive:
            return False
        if mod.requires_keys and not VAULT.has_all(mod.requires_keys):
            return False
        return True

    async def stream(self) -> AsyncIterator[dict]:
        if self.query.is_empty():
            yield {"type": "error", "message": "no identifiers provided"}
            return

        queue: asyncio.Queue = asyncio.Queue()
        collected: list[Finding] = []

        async def emit_finding(f: Finding) -> None:
            collected.append(f)
            await queue.put(f)

        # next_frontier is rebound each wave; the closure reads the current one.
        state = {"next": []}

        async def emit_artifact(a: Artifact) -> None:
            if a.parent_key:  # always record provenance, even for dup/oob nodes
                self.edges.append(_Edge(a.parent_key, a.key, a.source_module, a.data.get("edge", {})))
            if not self._admit_node(a):
                return
            if self._should_expand(a):
                state["next"].append(a)

        async def worker() -> None:
            async with RateLimitedClient(self.settings) as client:
                ctx = ModuleContext(
                    client=client, query=self.query, settings=self.settings,
                    in_scope=self.scope.in_scope,
                    _emit_finding=emit_finding, _emit_artifact=emit_artifact,
                )
                # Seed the frontier (seeds are always admitted + expanded).
                frontier: list[Artifact] = []
                for seed in self.query.to_seed_artifacts():
                    if self._admit_node(seed):
                        frontier.append(seed)

                while frontier:
                    if self._requests >= self.settings.max_requests:
                        self.stop_reason = self.stop_reason or "max_requests reached"
                        break
                    state["next"] = []
                    tasks = []
                    for art in frontier:
                        for mod in applicable_modules(art):
                            if not self._module_enabled(mod):
                                continue
                            if self._requests >= self.settings.max_requests:
                                self.stop_reason = self.stop_reason or "max_requests reached"
                                break
                            self._requests += 1
                            tasks.append(mod.run_resilient(art, ctx))
                    await asyncio.gather(*tasks, return_exceptions=True)
                    frontier = state["next"]
            await queue.put(None)  # sentinel

        task = asyncio.create_task(worker())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield {"type": "finding", "finding": item.model_dump()}
        finally:
            await task

        identities = cluster([f for f in collected if f.is_hit])
        yield {"type": "summary", "summary": score.summarize(identities)}
        yield {
            "type": "done",
            "total": len(collected),
            "hits": sum(1 for f in collected if f.is_hit),
            "artifacts": len(self.artifacts),
            "stop_reason": self.stop_reason,
        }
