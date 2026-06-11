"""Acceptance gate for the core objective: soft-404s (200 but no real page)
must NOT be reported as FOUND, while genuine profiles must be."""

from recon.models import Evidence, SiteRule, Verdict
from recon.verify import similarity
from recon.verify.verdict import decide

ABSENT_BODY = """
<html><head><title>Page not found</title></head>
<body><h1>Sorry</h1><p>The page you requested could not be found.</p>
<nav>Home About Help</nav></body></html>
"""

# Same generic page returned for a non-existent user (soft 404): 200 + identical body.
SOFT404_BODY = ABSENT_BODY

GENUINE_BODY = """
<html><head><title>alice (Alice Doe) · Profile</title></head>
<body><h1>alice</h1><p>Software engineer. 412 followers. Joined 2014.</p>
<div class='repos'>awesome-thing, dotfiles, neural-net</div></body></html>
"""


def _ev(url, status, body, final=None, query=None):
    return Evidence(
        url=url,
        status=status,
        final_url=final or url,
        body_len=len(body),
        fingerprint=similarity.fingerprint_hex(body),
        title=similarity.extract_title(body),
        contains_query=bool(query) and query.lower() in body.lower(),
    )


def test_soft_404_is_not_found():
    """The headline case: 200 OK but the body is the site's generic not-found."""
    rule = SiteRule(name="SoftSite", uri_check="https://s.example/u/{account}",
                    error_type="status_code")
    baseline = _ev("https://s.example/u/zzrandom", 200, ABSENT_BODY)
    ev = _ev("https://s.example/u/alice", 200, SOFT404_BODY, query="alice")
    verdict, conf, reasons, _ = decide(rule, ev, SOFT404_BODY, baseline)
    assert verdict == Verdict.NOT_FOUND, (verdict, conf, reasons)
    assert any("soft-404" in r for r in reasons)


def test_genuine_profile_is_found():
    rule = SiteRule(name="RealSite", uri_check="https://r.example/{account}",
                    error_type="status_code", error_code=404)
    baseline = _ev("https://r.example/zzrandom", 404, ABSENT_BODY)
    ev = _ev("https://r.example/alice", 200, GENUINE_BODY, query="alice")
    verdict, conf, reasons, _ = decide(rule, ev, GENUINE_BODY, baseline)
    assert verdict == Verdict.FOUND, (verdict, conf, reasons)
    assert conf >= 0.75


def test_hard_404_is_not_found():
    rule = SiteRule(name="HardSite", uri_check="https://h.example/{account}",
                    error_type="status_code", error_code=404)
    baseline = _ev("https://h.example/zzrandom", 404, ABSENT_BODY)
    ev = _ev("https://h.example/ghost", 404, ABSENT_BODY)
    verdict, conf, reasons, _ = decide(rule, ev, ABSENT_BODY, baseline)
    assert verdict == Verdict.NOT_FOUND


def test_message_rule_detects_absent():
    rule = SiteRule(name="MsgSite", uri_check="https://m.example/{account}",
                    error_type="message", error_msg=["could not be found"])
    baseline = _ev("https://m.example/zzrandom", 200, ABSENT_BODY)
    ev = _ev("https://m.example/ghost", 200, ABSENT_BODY)
    verdict, conf, reasons, _ = decide(rule, ev, ABSENT_BODY, baseline)
    assert verdict == Verdict.NOT_FOUND
    assert any("error message" in r for r in reasons)


def test_bare_200_without_baseline_is_uncertain_not_found():
    """No baseline + only a 200 must never be a confident FOUND."""
    rule = SiteRule(name="NoBase", uri_check="https://n.example/{account}",
                    error_type="status_code")
    ev = _ev("https://n.example/alice", 200, GENUINE_BODY)  # no query match
    verdict, conf, reasons, _ = decide(rule, ev, GENUINE_BODY, baseline=None)
    assert verdict == Verdict.UNCERTAIN, (verdict, conf, reasons)
    assert conf < 0.75
