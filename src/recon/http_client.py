"""Shared async HTTP client with per-host rate limiting and robots.txt respect.

A single AsyncClient is reused for connection pooling / HTTP-2. All collectors
go through `fetch()` so compliance (UA, rate limit, robots) is centralized.
"""

from __future__ import annotations

import asyncio
import time
import urllib.robotparser as robotparser
from typing import Optional
from urllib.parse import urlsplit

import httpx

from .config import SETTINGS


class RateLimitedClient:
    def __init__(self, settings=SETTINGS, limiter=None) -> None:
        self.s = settings
        self._client: Optional[httpx.AsyncClient] = None
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._host_last: dict[str, float] = {}
        self._robots: dict[str, Optional[robotparser.RobotFileParser]] = {}
        # Optional cross-process limiter (e.g. Redis) for the distributed path.
        self._limiter = limiter
        # Count of real outbound requests, so the engine can enforce a budget
        # against actual traffic rather than module dispatches (one dispatch of
        # the username module can fan out to hundreds of site checks).
        self.request_count = 0

    async def __aenter__(self) -> "RateLimitedClient":
        self._client = httpx.AsyncClient(
            http2=True,
            follow_redirects=True,
            timeout=self.s.request_timeout,
            max_redirects=self.s.max_redirects,
            headers={"User-Agent": self.s.user_agent},
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    def _host_lock(self, host: str) -> asyncio.Lock:
        if host not in self._host_locks:
            self._host_locks[host] = asyncio.Lock()
        return self._host_locks[host]

    async def _allowed_by_robots(self, url: str) -> bool:
        if not self.s.respect_robots:
            return True
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._robots:
            rp = robotparser.RobotFileParser()
            try:
                assert self._client is not None
                r = await self._client.get(f"{origin}/robots.txt")
                if r.status_code == 200:
                    rp.parse(r.text.splitlines())
                else:
                    rp = None  # no usable robots -> allow
            except Exception:
                rp = None
            self._robots[origin] = rp
        rp = self._robots[origin]
        if rp is None:
            return True
        return rp.can_fetch(self.s.user_agent, url)

    async def fetch(self, url: str, method: str = "GET") -> httpx.Response:
        """Rate-limited, robots-respecting fetch. Raises httpx errors on failure."""
        assert self._client is not None, "use as async context manager"
        host = urlsplit(url).netloc

        if not await self._allowed_by_robots(url):
            raise PermissionError(f"blocked by robots.txt: {url}")

        async with self._sem:
            lock = self._host_lock(host)
            async with lock:
                wait = self.s.per_host_min_interval - (
                    time.monotonic() - self._host_last.get(host, 0.0)
                )
                if wait > 0:
                    await asyncio.sleep(wait)
                self._host_last[host] = time.monotonic()
            # Cross-process politeness (no-op unless a distributed limiter is set).
            if self._limiter is not None:
                await self._limiter.acquire(host)
            self.request_count += 1
            resp = await self._client.request(method, url)
            return resp
