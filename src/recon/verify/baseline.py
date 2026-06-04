"""Layer 0: control-probe baseline.

For each host we request a *known-absent* random account and remember how the
site answers "no such user": status, final URL, body length, fingerprint.
Later we diff the real response against this — the single most effective way to
kill soft-404 false positives, because it adapts to each site automatically.
"""

from __future__ import annotations

import secrets
import string
from typing import Optional

from ..config import SETTINGS
from ..http_client import RateLimitedClient
from ..models import Evidence, SiteRule
from . import similarity


def random_absent_account(length: int | None = None) -> str:
    n = length or SETTINGS.control_probe_len
    alphabet = string.ascii_lowercase + string.digits
    # Prefix unlikely to ever be a real handle.
    return "zz" + "".join(secrets.choice(alphabet) for _ in range(n))


async def evidence_from_response(url: str, resp, elapsed_ms: int = 0,
                                 query_term: Optional[str] = None) -> Evidence:
    body = resp.text[: SETTINGS.max_body_bytes]
    title = similarity.extract_title(body)
    contains = bool(query_term) and query_term.lower() in body.lower()
    return Evidence(
        url=url,
        status=resp.status_code,
        final_url=str(resp.url),
        body_len=len(body),
        fingerprint=similarity.fingerprint_hex(body),
        title=title,
        contains_query=contains,
        elapsed_ms=elapsed_ms,
    )


class BaselineCache:
    """Per-(host) cache of absent-account evidence, computed at most once."""

    def __init__(self, client: RateLimitedClient) -> None:
        self._client = client
        self._cache: dict[str, Optional[Evidence]] = {}

    async def get(self, rule: SiteRule) -> Optional[Evidence]:
        key = rule.name
        if key in self._cache:
            return self._cache[key]
        probe = random_absent_account()
        url = rule.url_for(probe)
        try:
            resp = await self._client.fetch(url)
            ev = await evidence_from_response(url, resp, query_term=probe)
        except Exception as e:  # noqa: BLE001 - baseline is best-effort
            ev = Evidence(
                url=url, status=0, final_url=url, body_len=0,
                fingerprint="", error=str(e),
            )
        self._cache[key] = ev
        return ev
