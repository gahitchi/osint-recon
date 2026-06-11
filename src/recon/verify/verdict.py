"""Layer 4: combine all signals into an explainable verdict.

Design goal: minimize false positives. We never emit FOUND on a bare 200.
A 200 only becomes FOUND when corroborated by the site's own absent-baseline
(different status/redirect) or by clear content divergence + positive signals.
Otherwise it is downgraded to UNCERTAIN — shown to the user, flagged, never
silently reported as a real hit.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..config import SETTINGS
from ..explain import ScoreBreakdown
from ..models import Evidence, SiteRule, Verdict
from . import rules as rules_mod
from .similarity import similarity_hex


def _same_path(a: str, b: str) -> bool:
    try:
        return urlsplit(a).path.rstrip("/") == urlsplit(b).path.rstrip("/")
    except Exception:
        return False


def _terminal(verdict: Verdict, term: str, reason: str) -> tuple[Verdict, float, list[str], ScoreBreakdown]:
    """A short-circuit verdict (ERROR/UNVERIFIABLE) with a trivial breakdown."""
    bd = ScoreBreakdown(base=0.0)
    bd.add(term, 0.0, reason)
    bd.finalize()
    return verdict, 0.0, [reason], bd


def decide(
    rule: SiteRule,
    ev: Evidence,
    body: str,
    baseline: Evidence | None,
    settings=SETTINGS,
) -> tuple[Verdict, float, list[str], ScoreBreakdown]:
    reasons: list[str] = []
    bd = ScoreBreakdown(base=0.5)  # neutral prior on "this account exists"

    if ev.status == 0 or ev.error:
        return _terminal(Verdict.ERROR, "error", f"request failed: {ev.error or 'no response'}")

    # Layer 0.5 — adversarial defense: a bot-wall/WAF/JS-gate/rate-limit means we
    # genuinely cannot tell if the account exists. Report it honestly instead of
    # emitting a false FOUND (challenge page) or false NOT_FOUND (block).
    if ev.blocked:
        return _terminal(Verdict.UNVERIFIABLE, "blocked", f"response was a {ev.blocked}")
    if baseline is not None and baseline.blocked:
        return _terminal(Verdict.UNVERIFIABLE, "baseline_blocked",
                         f"site's absent-baseline was a {baseline.blocked}; cannot calibrate")

    # --- Layer 1: declared site rule ---
    present, rreason = rules_mod.eval_rule(rule, ev, body)
    reasons.append(rreason)
    if present is True:
        bd.add("site_rule", 0.15, rreason)
    elif present is False:
        bd.add("site_rule", -0.45, rreason)
    else:
        bd.add("site_rule", 0.0, rreason)

    have_baseline = baseline is not None and baseline.status != 0

    # --- Layer 2: redirect / final-URL vs absent baseline ---
    if have_baseline:
        if _same_path(ev.final_url, baseline.final_url) and not _same_path(
            ev.final_url, ev.url
        ):
            r = f"redirected to same location as absent baseline ({ev.final_url})"
            bd.add("redirect_to_baseline", -0.40, r)
            reasons.append(r)
        if baseline.status != ev.status:
            r = (f"status {ev.status} differs from absent-baseline status "
                 f"{baseline.status} (site distinguishes missing accounts)")
            bd.add("status_vs_baseline", 0.20, r)
            reasons.append(r)

    # --- Layer 3: content fingerprint diff vs absent baseline ---
    if have_baseline and baseline.fingerprint and ev.fingerprint:
        sim = similarity_hex(ev.fingerprint, baseline.fingerprint)
        if sim >= settings.baseline_similarity_reject:
            r = f"body {sim:.2f} similar to absent baseline -> soft-404 rejected"
            bd.add("soft404_reject", -0.50, r)
            reasons.append(r)
        elif sim <= 0.50:
            r = f"body clearly differs from absent baseline (sim {sim:.2f})"
            bd.add("content_differs", 0.20, r)
            reasons.append(r)
        else:
            reasons.append(f"body partially similar to absent baseline (sim {sim:.2f})")
    elif not have_baseline:
        r = "no absent-baseline available -> reduced confidence"
        bd.add("no_baseline", 0.0, r)
        reasons.append(r)

    # --- Layer 3b: positive content signals ---
    if ev.contains_query:
        r = "queried term present in page body"
        bd.add("query_in_body", 0.20, r)
        reasons.append(r)

    bd.finalize()
    score = bd.total

    if score >= settings.found_confidence:
        verdict = Verdict.FOUND
    elif score >= settings.uncertain_confidence:
        verdict = Verdict.UNCERTAIN
    else:
        verdict = Verdict.NOT_FOUND

    return verdict, score, reasons, bd
