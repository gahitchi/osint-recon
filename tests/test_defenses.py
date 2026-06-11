"""Adversarial defense detection -> UNVERIFIABLE (never a false FOUND/NOT_FOUND)."""

from recon.models import Evidence, SiteRule, Verdict
from recon.verify import defenses, similarity
from recon.verify.verdict import decide


def _ev(status, body, blocked=None, url="https://s/u/x"):
    return Evidence(url=url, status=status, final_url=url, body_len=len(body),
                    fingerprint=similarity.fingerprint_hex(body),
                    contains_query=True, blocked=blocked)


def test_detect_cloudflare_challenge():
    body = "<html><head><title>Just a moment...</title></head><body>" \
           "Checking your browser before accessing. cf-browser-verification</body></html>"
    assert defenses.detect(503, {"server": "cloudflare", "cf-ray": "abc"}, body)


def test_detect_rate_limit():
    assert defenses.detect(429, {}, "")
    assert defenses.detect(200, {"retry-after": "30"}, "ok")


def test_detect_captcha_and_generic_block():
    assert defenses.detect(200, {}, "<div class='g-recaptcha'></div>")
    assert defenses.detect(403, {}, "Access to this page has been denied")


def test_clean_page_is_not_flagged():
    assert defenses.detect(200, {"server": "nginx"}, "<h1>alice</h1> real profile content") is None


def test_blocked_response_is_unverifiable_not_found():
    """A 200 challenge page that contains the username must NOT become FOUND."""
    rule = SiteRule(name="S", uri_check="https://s/u/{account}", error_type="status_code")
    ev = _ev(200, "Just a moment... checking your browser", blocked="Cloudflare bot-challenge")
    verdict, conf, reasons, _ = decide(rule, ev, "Just a moment...", baseline=None)
    assert verdict == Verdict.UNVERIFIABLE
    assert conf == 0.0
    assert any("Cloudflare" in r for r in reasons)


def test_blocked_baseline_makes_target_unverifiable():
    rule = SiteRule(name="S", uri_check="https://s/u/{account}", error_type="status_code")
    base = _ev(403, "Access denied", blocked="WAF/anti-bot block", url="https://s/u/zz")
    ev = _ev(200, "<h1>alice</h1>")
    verdict, _, reasons, _ = decide(rule, ev, "<h1>alice</h1>", baseline=base)
    assert verdict == Verdict.UNVERIFIABLE
