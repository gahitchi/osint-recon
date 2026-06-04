"""Body normalization + SimHash fingerprinting + similarity.

Used to detect "soft 404s": pages that return 200 but are really the site's
generic not-found/landing page. We compare a response against the site's own
known-absent baseline instead of relying on status codes alone.
"""

from __future__ import annotations

import hashlib
import re

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
# Volatile tokens that differ between identical pages (csrf, nonces, timestamps).
_VOLATILE_RE = re.compile(
    r"(csrf[-_]?token|nonce|request[-_]?id|[0-9a-f]{16,}|\d{10,}|"
    r"\d{4}-\d{2}-\d{2}t[\d:.\-+z]+)",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL | re.IGNORECASE)


def extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    return _WS_RE.sub(" ", _HTML_TAG_RE.sub("", m.group(1))).strip() or None


def normalize(html: str) -> str:
    """Strip scripts/styles/markup and volatile tokens, collapse whitespace."""
    text = _TAG_RE.sub(" ", html)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _VOLATILE_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text)
    return text.strip().lower()


def _shingles(text: str, k: int = 4) -> list[str]:
    tokens = text.split()
    if len(tokens) < k:
        return tokens or [text]
    return [" ".join(tokens[i : i + k]) for i in range(len(tokens) - k + 1)]


def simhash(html: str, bits: int = 64) -> int:
    """64-bit SimHash over k-shingles of the normalized body."""
    v = [0] * bits
    for sh in _shingles(normalize(html)):
        h = int.from_bytes(
            hashlib.blake2b(sh.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if v[i] > 0:
            out |= 1 << i
    return out


def fingerprint_hex(html: str) -> str:
    return f"{simhash(html):016x}"


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def similarity_hex(fp_a: str, fp_b: str, bits: int = 64) -> float:
    """1.0 == identical fingerprints, 0.0 == maximally different."""
    if not fp_a or not fp_b:
        return 0.0
    try:
        a, b = int(fp_a, 16), int(fp_b, 16)
    except ValueError:
        return 0.0
    return 1.0 - (_hamming(a, b) / bits)
