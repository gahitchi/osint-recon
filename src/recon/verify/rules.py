"""Layer 1: per-site rule evaluation (WhatsMyName-style).

Returns a tri-state hint plus a human reason. None == rule inconclusive,
so the verdict falls through to baseline/similarity layers.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

from ..models import Evidence, SiteRule


def _error_msgs(rule: SiteRule) -> list[str]:
    em = rule.error_msg
    if em is None:
        return []
    if isinstance(em, str):
        return [em]
    return [str(x) for x in em]


def eval_rule(rule: SiteRule, ev: Evidence, body: str) -> tuple[Optional[bool], str]:
    """Evaluate the site's declared detection rule against the response.

    Returns (present, reason): present=True -> rule says account exists,
    False -> rule says absent, None -> rule could not decide.
    """
    if ev.status == 0:
        return None, "no response"

    etype = (rule.error_type or "status_code").lower()

    if etype == "status_code":
        ok_code = rule.error_code  # for wmn this is the *not found* code
        if ok_code is not None:
            if ev.status == ok_code:
                return False, f"rule: not-found status {ev.status}"
            if ev.status == 200:
                return True, "rule: status 200 and not the not-found code"
            return None, f"rule: ambiguous status {ev.status}"
        # default convention: 200 present, anything else absent
        if ev.status == 200:
            return True, "rule: status 200"
        return False, f"rule: status {ev.status}"

    if etype == "message":
        msgs = _error_msgs(rule)
        low = body.lower()
        for m in msgs:
            if m and m.lower() in low:
                return False, f"rule: error message present ({m!r})"
        if ev.status == 200:
            return True, "rule: 200 and no error message in body"
        return None, f"rule: status {ev.status}, no error message"

    if etype == "response_url":
        if rule.error_url:
            tmpl = urlsplit(rule.error_url.replace("{account}", "")).path
            if tmpl and tmpl in urlsplit(ev.final_url).path:
                return False, f"rule: redirected to error url ({ev.final_url})"
            return True if ev.status == 200 else None, "rule: not at error url"
        return None, "rule: response_url type but no error_url"

    return None, f"rule: unknown error_type {etype!r}"
