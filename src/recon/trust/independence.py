"""Source-independence tracking.

Corroboration is only as strong as the *independence* of the sources backing it.
The breadth bonus in `correlate/confidence.py` and `score.py` historically counted
distinct source *names* — but many sources share an upstream and aren't
independent evidence: Team Cymru, RIPEstat and ip-api all reflect RIR/whois data;
a GitHub profile and a harvested GitHub commit-email both come from GitHub. Three
such "confirmations" are really one line of evidence.

This maps each source to an *independence class* (its upstream lineage) so breadth
can be measured over distinct classes, not names. The mapping is declarative and
overridable via ``RECON_INDEPENDENCE_FILE`` (JSON: ``{"token": "class"}``), in the
same spirit as the rules engine.

Phase 5a uses this in *shadow* mode (displayed, not applied); the flip to the
official score is gated by ``Settings.confidence_independence`` once calibration
validates it.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache

from .. import normalize

# Token found in a source/module name -> independence class (shared upstream).
# Username site-checks are handled separately: each platform is its own class.
_CLASS_TOKENS: dict[str, str] = {
    "team_cymru": "rir", "cymru": "rir", "asn": "rir",
    "ripestat": "rir", "ip_geo": "rir", "ip-api": "rir", "abuseipdb": "rir",
    "gravatar": "gravatar",
    "github": "github",
    "crt.sh": "ct_log", "crtsh": "ct_log",
    "wayback": "web_archive",
    "commoncrawl": "web_crawl",
    "breach": "breach", "xposed": "breach", "hibp": "breach",
    "dns": "dns", "dns_intel": "dns", "domain": "dns",
    "shodan": "shodan",
    "virustotal": "virustotal",
    "orcid": "scholar", "openalex": "scholar", "name": "scholar",
    "phone": "phone_offline",
    "gravatar_hash": "gravatar",
}


@lru_cache(maxsize=1)
def _overrides() -> dict[str, str]:
    path = os.environ.get("RECON_INDEPENDENCE_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return {str(k).lower(): str(v) for k, v in json.load(fh).items()}
    return {}


def reload() -> None:
    """Forget any cached override file (tests / runtime changes)."""
    _overrides.cache_clear()


def class_of(source: str) -> str:
    """The independence class for a finding source or module name.

    A username site-check (``username:GitHub``) is independent *per platform*, so
    each platform becomes ``site:<platform>``. Everything else is matched against
    the lineage token map; unknown sources are treated as their own class (i.e.
    independent) using their leading token."""
    s = (source or "").strip().lower()
    if not s:
        return "unknown"
    if s in _overrides():
        return _overrides()[s]
    prefix, _, rest = s.partition(":")
    if prefix == "username" and rest:
        return "site:" + (normalize.fold_handle(rest) or rest)
    for token, cls in {**_CLASS_TOKENS, **_overrides()}.items():
        if token in s:
            return cls
    return prefix or s


def independent_classes(sources) -> tuple[set[str], list[tuple[str, str]]]:
    """Map sources to classes. Returns (distinct classes, redundant pairs) where
    a redundant pair is a (source, class) collapsed into an already-counted class."""
    classes: set[str] = set()
    redundant: list[tuple[str, str]] = []
    for src in sources:
        cls = class_of(src)
        if cls in classes:
            redundant.append((src, cls))
        else:
            classes.add(cls)
    return classes, redundant


def independence_breadth(sources, per: float = 0.08, cap: float = 0.25) -> float:
    """Breadth bonus from *independent* corroboration: scales with distinct
    classes, not source count. Mirrors the existing name-based formula's shape so
    the two are directly comparable in a score breakdown."""
    classes, _ = independent_classes(sources)
    return min(cap, per * max(0, len(classes) - 1))
