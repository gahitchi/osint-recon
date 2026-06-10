"""Module interface + the resilience wrapper that runs one module against one
artifact (cache replay + circuit breaker + reliability bookkeeping).

The resilience logic mirrors `connectors/base.Connector.run`, but operates on an
Artifact rather than a whole Query, and caches BOTH the findings a module emits
and the artifacts it produces — so a cache hit still drives recursion forward.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from ..config import Settings
from ..connectors import cache
from ..graph_models import Artifact, ArtifactType
from ..http_client import RateLimitedClient
from ..models import Finding, Query, Verdict

EmitFinding = Callable[[Finding], Awaitable[None]]
EmitArtifact = Callable[[Artifact], Awaitable[None]]


@dataclass
class ModuleContext:
    """What a module is handed when it runs. Modules grow the graph through
    `emit_artifact` and report evidence through `emit_finding`; the two are
    decoupled (a finding need not yield an artifact, and vice versa)."""

    client: RateLimitedClient
    query: Query                       # the original seed identifiers
    settings: Settings
    in_scope: Callable[[Artifact], bool]
    _emit_finding: EmitFinding
    _emit_artifact: EmitArtifact

    async def emit_finding(self, f: Finding) -> None:
        await self._emit_finding(f)

    async def emit_artifact(self, a: Artifact) -> None:
        await self._emit_artifact(a)

    def child(self, _emit_finding: EmitFinding, _emit_artifact: EmitArtifact) -> "ModuleContext":
        """A ctx with the same wiring but redirected emitters (used to capture
        a module's output for caching before forwarding it on)."""
        return ModuleContext(
            client=self.client, query=self.query, settings=self.settings,
            in_scope=self.in_scope, _emit_finding=_emit_finding,
            _emit_artifact=_emit_artifact,
        )


ModuleFn = Callable[[Artifact, ModuleContext], Awaitable[None]]


@dataclass
class Module:
    name: str
    consumes: set[ArtifactType]
    produces: set[ArtifactType]
    run: ModuleFn
    reliability_prior: float = 0.5
    requires_keys: list[str] = field(default_factory=list)
    passive: bool = True           # active modules touch the target more directly
    use_cache: bool = True
    enabled: bool = True

    @property
    def kind_label(self) -> str:
        """A stable 'kind' for the Source/breaker row (first consumed type)."""
        return next((t.value for t in sorted(self.consumes, key=lambda x: x.value)), "module")

    def accepts(self, art: Artifact) -> bool:
        return self.enabled and art.type in self.consumes

    async def run_resilient(self, art: Artifact, ctx: ModuleContext) -> None:
        """Run with cache + breaker + reliability; never raises. A failing
        module degrades gracefully and the rest of the scan proceeds."""
        rel = await asyncio.to_thread(
            cache.current_reliability, self.name, self.kind_label, self.reliability_prior
        )
        ckey = f"{self.name}:{art.key}"

        # 1) Cache: replay prior findings + artifacts instead of hitting sources.
        if self.use_cache:
            cached = await asyncio.to_thread(cache.get_cached_key, ckey)
            if cached is not None:
                for fd in cached.get("findings", []):
                    f = Finding(**fd)
                    f.reasons = [*f.reasons, "(from cache)"]
                    f.data = {**f.data, "source_reliability": rel}
                    await ctx.emit_finding(f)
                for ad in cached.get("artifacts", []):
                    await ctx.emit_artifact(Artifact(**ad))
                return

        # 2) Circuit breaker: skip dead sources during cooldown.
        if await asyncio.to_thread(cache.breaker_open, self.name, self.kind_label,
                                   self.reliability_prior):
            await ctx.emit_finding(Finding(
                source=self.name, category=self.kind_label, label=self.name,
                verdict=Verdict.ERROR, confidence=0.0,
                reasons=["source circuit-breaker open (skipped, will retry later)"],
            ))
            return

        # 3) Run the module, buffering output so we can cache it.
        buf_f: list[Finding] = []
        buf_a: list[Artifact] = []

        async def capture_finding(f: Finding) -> None:
            f.data = {**f.data, "source_reliability": rel}
            buf_f.append(f)
            await ctx.emit_finding(f)

        async def capture_artifact(a: Artifact) -> None:
            buf_a.append(a)
            await ctx.emit_artifact(a)

        cctx = ctx.child(capture_finding, capture_artifact)
        try:
            await self.run(art, cctx)
        except Exception as e:  # noqa: BLE001 - isolate module failures
            await asyncio.to_thread(cache.record_failure, self.name, self.kind_label,
                                    self.reliability_prior, str(e))
            await ctx.emit_finding(Finding(
                source=self.name, category=self.kind_label, label=self.name,
                verdict=Verdict.ERROR, reasons=[f"module failed: {e}"],
            ))
            return

        # 4) Health bookkeeping: an all-ERROR result counts as a failure.
        non_error = [f for f in buf_f if f.verdict != Verdict.ERROR]
        if buf_f and not non_error:
            await asyncio.to_thread(cache.record_failure, self.name, self.kind_label,
                                    self.reliability_prior, "all results errored")
        else:
            await asyncio.to_thread(cache.record_success, self.name, self.kind_label,
                                    self.reliability_prior)
            if self.use_cache and (non_error or buf_a):
                await asyncio.to_thread(cache.set_cached_key, ckey, {
                    "findings": [f.model_dump() for f in buf_f],
                    "artifacts": [a.model_dump() for a in buf_a],
                })
