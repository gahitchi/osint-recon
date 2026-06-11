"""Built-in correlation rules + the loader that merges in user rules.

Each rule is a plain dict (the declarative form). Users can add or override
rules by pointing ``RECON_RULES_FILE`` at a JSON file containing a list of the
same shape; rules there replace built-ins with the same ``id``.

Every rule here fires on artifact types the engine actually emits (verified
against `src/recon/modules/`), so the defaults produce real insights — not
hypotheticals — on a normal scan.
"""

from __future__ import annotations

import json
import os

from .model import Rule

DEFAULT_RULES: list[dict] = [
    {
        "id": "email-in-breach",
        "title": "Email address exposed in a known breach",
        "severity": "medium",
        "kind": "threshold",
        "match": [{"type": "breach"}],
        "min_count": 1,
        "description": "A harvested email appears in one or more public breach "
                       "corpora — credentials for it may be circulating.",
    },
    {
        "id": "handle-reuse-breached",
        "title": "Reused handle tied to a breached email",
        "severity": "high",
        "kind": "co_occurrence",
        "join": "handle",
        "match": [{"type": "username"}, {"type": "breach"}],
        "description": "The same handle was seen as a username and as the local "
                       "part of an email found in a breach — a strong link between "
                       "the online persona and exposed credentials.",
    },
    {
        "id": "avatar-reuse",
        "title": "Same avatar reused across accounts",
        "severity": "high",
        "kind": "shared",
        "group_by": "value",
        "distinct": "parent",
        "min_distinct": 2,
        "match": [{"type": "hash"}],
        "description": "One avatar hash (e.g. Gravatar) is shared by two or more "
                       "distinct accounts/emails — a high-confidence same-person link.",
    },
    {
        "id": "handle-across-platforms",
        "title": "Handle reused across many platforms",
        "severity": "medium",
        "kind": "shared",
        "group_by": "handle",
        "distinct": "platform",
        "min_distinct": 3,
        "match": [{"type": "account_profile"}],
        "description": "The same folded handle resolves to verified profiles on "
                       "three or more distinct platforms — consistent persona reuse.",
    },
    {
        "id": "broad-subdomain-footprint",
        "title": "Broad subdomain footprint",
        "severity": "low",
        "kind": "threshold",
        "match": [{"type": "subdomain"}],
        "min_count": 8,
        "description": "Many subdomains were discovered for the target domain — a "
                       "large externally-visible attack surface worth enumerating.",
    },
    {
        "id": "multi-network-infra",
        "title": "Infrastructure spread across multiple networks",
        "severity": "info",
        "kind": "threshold",
        "match": [{"type": "asn"}],
        "min_count": 2,
        "description": "The target's hosts resolve into two or more autonomous "
                       "systems — multi-provider or CDN-fronted infrastructure.",
    },
]


def load_rules() -> list[Rule]:
    """Built-in rules, with any ``RECON_RULES_FILE`` rules merged in (same id
    overrides). Returns parsed `Rule` objects."""
    by_id = {r["id"]: r for r in DEFAULT_RULES}
    path = os.environ.get("RECON_RULES_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            extra = json.load(fh)
        for r in extra:
            by_id[r["id"]] = r
    return [Rule.from_dict(d) for d in by_id.values()]


def rule_catalogue() -> list[dict]:
    """Lightweight description of every loaded rule, for the API/UI."""
    return [
        {"id": r.id, "title": r.title, "severity": r.severity.value,
         "kind": r.kind, "description": r.description}
        for r in load_rules()
    ]
