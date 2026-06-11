"""Phase-5a score explainability: the structured breakdown is faithful — its
terms sum to the reported confidence, and named layers appear as contributions."""

from recon.models import Evidence, SiteRule, Verdict
from recon.verify import similarity
from recon.verify.verdict import decide

ABSENT = "<html><title>not found</title><body>no such user here</body></html>"
GENUINE = "<html><title>alice profile</title><body>alice — 412 followers, repos</body></html>"


def _ev(url, status, body, final=None, query=None):
    return Evidence(url=url, status=status, final_url=final or url, body_len=len(body),
                    fingerprint=similarity.fingerprint_hex(body),
                    title=similarity.extract_title(body),
                    contains_query=bool(query) and query.lower() in body.lower())


def _sums_to_total(bd):
    return abs(round(bd.base + sum(c.delta for c in bd.contributions), 3) - bd.total) < 1e-6 \
        or bd.total in (0.0, 1.0)  # clamped at the rails


def test_breakdown_terms_sum_to_confidence():
    rule = SiteRule(name="R", uri_check="https://r/{account}",
                    error_type="status_code", error_code=404)
    base = _ev("https://r/zzabsent", 404, ABSENT)
    ev = _ev("https://r/alice", 200, GENUINE, query="alice")
    verdict, conf, reasons, bd = decide(rule, ev, GENUINE, base)
    assert verdict == Verdict.FOUND
    assert bd.total == conf
    assert _sums_to_total(bd)
    # The status-vs-baseline corroboration is captured as a positive term.
    assert any(c.term == "status_vs_baseline" and c.delta > 0 for c in bd.contributions)


def test_soft404_breakdown_has_negative_reject_term():
    rule = SiteRule(name="S", uri_check="https://s/{account}", error_type="status_code")
    base = _ev("https://s/zzabsent", 200, ABSENT)
    ev = _ev("https://s/ghost", 200, ABSENT)          # identical body => soft-404
    verdict, conf, reasons, bd = decide(rule, ev, ABSENT, base)
    assert verdict == Verdict.NOT_FOUND
    assert any(c.term == "soft404_reject" and c.delta < 0 for c in bd.contributions)
    assert bd.total == conf


def test_terminal_verdicts_have_trivial_breakdown():
    rule = SiteRule(name="B", uri_check="https://b/{account}", error_type="status_code")
    ev = _ev("https://b/u", 200, "Just a moment…")
    ev.blocked = "Cloudflare bot-challenge"
    verdict, conf, reasons, bd = decide(rule, ev, "x", None)
    assert verdict == Verdict.UNVERIFIABLE
    assert conf == 0.0 and bd.total == 0.0
    assert bd.contributions and bd.contributions[0].term == "blocked"


def test_base_prior_is_half():
    rule = SiteRule(name="N", uri_check="https://n/{account}", error_type="status_code")
    ev = _ev("https://n/alice", 200, GENUINE)         # no baseline, bare 200
    _, conf, _, bd = decide(rule, ev, GENUINE, None)
    assert bd.base == 0.5
    assert _sums_to_total(bd)
