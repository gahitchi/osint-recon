"""Adversarial web-defense detection (#5).

Modern sites front profiles with bot-walls, WAFs, JS gates, and rate limits.
A challenge page typically returns HTTP 200/403/429/503 with a generic body —
exactly the shape that produces false positives ("found!") or false negatives
("not found") in naive recon. Instead of guessing, we detect the defense and let
the verdict layer mark the result UNVERIFIABLE: honest, and immune to soft-404
breakage under bot detection.

detect() takes status, headers (case-insensitive mapping or dict), and body, and
returns a human reason string, or None when no defense is detected.
"""

from __future__ import annotations

from typing import Mapping, Optional

# Body markers grouped by defense vendor / mechanism.
_CLOUDFLARE = (
    "just a moment", "checking your browser", "cf-browser-verification",
    "/cdn-cgi/challenge-platform", "attention required", "cloudflare ray id",
    "enable cookies and reload",
)
_AKAMAI = ("akamaighost", "reference #", "access denied", "errors.edgesuite.net")
_DATADOME = ("datadome", "geo.captcha-delivery.com")
_PERIMETERX = ("px-captcha", "/px/captcha", "perimeterx", "_pxhd")
_IMPERVA = ("incapsula incident", "_incapsula_", "imperva")
_CAPTCHA = ("g-recaptcha", "h-captcha", "hcaptcha.com/captcha", "please verify you are a human")
_GENERIC_BLOCK = ("access to this page has been denied", "request blocked",
                  "you have been blocked", "unusual traffic", "bot detected")
_JS_REQUIRED = ("please enable javascript", "javascript is required",
                "this site requires javascript", "noscript")


def _h(headers: Mapping[str, str] | None, key: str) -> str:
    if not headers:
        return ""
    # httpx.Headers is case-insensitive; plain dicts may not be.
    try:
        return str(headers.get(key, "") or "").lower()
    except Exception:
        return ""


def detect(status: int, headers: Mapping[str, str] | None, body: str) -> Optional[str]:
    low = (body or "").lower()
    server = _h(headers, "server")
    has_cf_ray = bool(_h(headers, "cf-ray")) or "cloudflare" in server
    is_challenge_status = status in (403, 429, 503, 401)

    # Rate limiting is its own honest signal.
    if status == 429 or _h(headers, "retry-after"):
        return "rate-limited (HTTP 429 / Retry-After) — existence not determinable"

    if any(m in low for m in _CLOUDFLARE) or (has_cf_ray and is_challenge_status):
        return "Cloudflare bot-challenge"
    if any(m in low for m in _DATADOME) or "datadome" in _h(headers, "set-cookie"):
        return "DataDome bot-challenge"
    if any(m in low for m in _PERIMETERX):
        return "PerimeterX bot-challenge"
    if any(m in low for m in _IMPERVA):
        return "Imperva/Incapsula block"
    if any(m in low for m in _AKAMAI) and is_challenge_status:
        return "Akamai block"
    if any(m in low for m in _CAPTCHA):
        return "CAPTCHA challenge"
    if any(m in low for m in _GENERIC_BLOCK):
        return "WAF/anti-bot block"

    # JS-only gate: tiny body that just asks for JavaScript and shows nothing.
    if status == 200 and len(low) < 2000 and any(m in low for m in _JS_REQUIRED):
        return "JavaScript-gated page (content not server-rendered)"

    return None
