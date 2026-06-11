"""Username collector: fan out across the site dataset and run every candidate
through the false-positive verification engine.

This is where the project's core promise lives — a site only becomes a Finding
with verdict FOUND after surviving baseline + rule + similarity layers.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Awaitable, Callable

from ..config import SETTINGS
from ..http_client import RateLimitedClient
from ..models import Finding, Query, SiteRule, Verdict
from ..provenance import finding_trace
from ..verify.baseline import BaselineCache, evidence_from_response
from ..verify.verdict import decide

EmitFn = Callable[[Finding], Awaitable[None]]


def _from_wmn(s: dict) -> dict:
    """Translate a raw WhatsMyName (wmn-data.json) site into this project's
    SiteRule schema. WMN encodes detection as exists/missing pairs
    (e_code/e_string + m_code/m_string); SiteRule is not-found-oriented
    (error_type/error_code/error_msg). The not-found 'message' is the strongest
    signal, so prefer m_string, then fall back to m_code. The multi-layer FP
    engine (baseline + similarity) compensates for the simpler rule."""
    out: dict = {
        "name": s["name"],
        "uri_check": s["uri_check"],
        "uri_pretty": s.get("uri_pretty"),
        "cat": s.get("cat"),
        "tags": [s["cat"]] if s.get("cat") else [],
    }
    if s.get("m_string"):
        out["error_type"] = "message"
        out["error_msg"] = s["m_string"]
    elif s.get("m_code") is not None:
        out["error_type"] = "status_code"
        out["error_code"] = s["m_code"]
    else:
        out["error_type"] = "status_code"
        out["error_code"] = 404
    return out


def _is_wmn(s: dict) -> bool:
    """A raw WhatsMyName entry has exists/missing fields and no error_type."""
    return "error_type" not in s and any(k in s for k in ("m_code", "m_string", "e_code"))


def load_sites(path: str | None = None) -> list[SiteRule]:
    p = Path(path or SETTINGS.sites_data_file)
    if not p.is_absolute():
        # resolve relative to project root (two parents up from this file's package)
        root = Path(__file__).resolve().parents[3]
        p = root / p
    raw = json.loads(p.read_text(encoding="utf-8"))
    rules: list[SiteRule] = []
    excluded = SETTINGS.excluded_site_tags
    for s in raw.get("sites", []):
        if _is_wmn(s):
            s = _from_wmn(s)
        tags = {t.lower() for t in s.get("tags", [])}
        if tags & excluded or s["name"].lower() in excluded:
            continue
        rules.append(SiteRule(**s))
    return rules


async def _check_site(
    rule: SiteRule,
    account: str,
    client: RateLimitedClient,
    baselines: BaselineCache,
) -> Finding:
    url = rule.url_for(account)
    base = await baselines.get(rule)
    started = time.monotonic()
    try:
        resp = await client.fetch(url)
        elapsed = int((time.monotonic() - started) * 1000)
        ev = await evidence_from_response(url, resp, elapsed, query_term=account)
        body = resp.text[: SETTINGS.max_body_bytes]
    except Exception as e:  # noqa: BLE001
        return Finding(
            source=f"username:{rule.name}",
            category="username",
            label=rule.name,
            url=rule.uri_pretty.replace("{account}", account) if rule.uri_pretty else url,
            verdict=Verdict.ERROR,
            confidence=0.0,
            reasons=[f"request failed: {e}"],
        )

    verdict, conf, reasons, breakdown = decide(rule, ev, body, base)
    signals: dict[str, str] = {}
    if verdict == Verdict.FOUND:
        signals[f"username:{rule.name.lower()}"] = account

    # Phase separation (#6): a hit only counts as 'verified' when it survived the
    # strict layers (a usable absent-baseline existed to calibrate against);
    # otherwise it's a 'discovery' candidate the user should treat as weaker.
    verified = base is not None and base.status != 0 and not base.blocked
    phase = "verified" if verified else "discovery"

    return Finding(
        source=f"username:{rule.name}",
        category="username",
        label=rule.name,
        url=(rule.uri_pretty.replace("{account}", account) if rule.uri_pretty else url),
        verdict=verdict,
        confidence=conf,
        reasons=reasons,
        breakdown=breakdown,
        trace=finding_trace(module="username", source=f"username:{rule.name}",
                            rule=rule, ev=ev, baseline=base),
        signals=signals,
        data={"status": ev.status, "title": ev.title, "final_url": ev.final_url,
              "fingerprint": ev.fingerprint, "phase": phase},
    )


async def collect(query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
    account = query.username
    if not account:
        return
    sites = load_sites()
    baselines = BaselineCache(client)
    import asyncio

    async def run(rule: SiteRule) -> None:
        finding = await _check_site(rule, account, client, baselines)
        await emit(finding)

    await asyncio.gather(*(run(r) for r in sites))
