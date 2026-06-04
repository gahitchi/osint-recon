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
from ..models import Evidence, SiteRule, Verdict
from . import rules as rules_mod
from .similarity import similarity_hex


def _same_path(a: str, b: str) -> bool:
    try:
        return urlsplit(a).path.rstrip("/") == urlsplit(b).path.rstrip("/")
    except Exception:
        return False


def decide(
    rule: SiteRule,
    ev: Evidence,
    body: str,
    baseline: Evidence | None,
    settings=SETTINGS,
) -> tuple[Verdict, float, list[str]]:
    reasons: list[str] = []

    if ev.status == 0 or ev.error:
        return Verdict.ERROR, 0.0, [f"request failed: {ev.error or 'no response'}"]

    score = 0.5  # neutral prior on "this account exists"

    # --- Layer 1: declared site rule ---
    present, rreason = rules_mod.eval_rule(rule, ev, body)
    reasons.append(rreason)
    if present is True:
        score += 0.15
    elif present is False:
        score -= 0.45

    have_baseline = baseline is not None and baseline.status != 0

    # --- Layer 2: redirect / final-URL vs absent baseline ---
    if have_baseline:
        if _same_path(ev.final_url, baseline.final_url) and not _same_path(
            ev.final_url, ev.url
        ):
            score -= 0.40
            reasons.append(
                f"redirected to same location as absent baseline ({ev.final_url})"
            )
        if baseline.status != ev.status:
            score += 0.20
            reasons.append(
                f"status {ev.status} differs from absent-baseline status "
                f"{baseline.status} (site distinguishes missing accounts)"
            )

    # --- Layer 3: content fingerprint diff vs absent baseline ---
    if have_baseline and baseline.fingerprint and ev.fingerprint:
        sim = similarity_hex(ev.fingerprint, baseline.fingerprint)
        if sim >= settings.baseline_similarity_reject:
            score -= 0.50
            reasons.append(
                f"body {sim:.2f} similar to absent baseline -> soft-404 rejected"
            )
        elif sim <= 0.50:
            score += 0.20
            reasons.append(f"body clearly differs from absent baseline (sim {sim:.2f})")
        else:
            reasons.append(f"body partially similar to absent baseline (sim {sim:.2f})")
    elif not have_baseline:
        reasons.append("no absent-baseline available -> reduced confidence")

    # --- Layer 3b: positive content signals ---
    if ev.contains_query:
        score += 0.20
        reasons.append("queried term present in page body")

    score = max(0.0, min(1.0, score))

    if score >= settings.found_confidence:
        verdict = Verdict.FOUND
    elif score >= settings.uncertain_confidence:
        verdict = Verdict.UNCERTAIN
    else:
        verdict = Verdict.NOT_FOUND

    return verdict, round(score, 3), reasons
