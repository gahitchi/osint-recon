"""Core data models shared across collectors, the verify engine, and reporting."""

from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Verdict(str, enum.Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNCERTAIN = "UNCERTAIN"
    # The response was a bot-wall / WAF challenge / JS-gate / rate-limit, so the
    # account's existence genuinely could not be determined. Reporting this
    # honestly prevents both false positives (challenge page that returns 200)
    # and false negatives (a block mistaken for "not found").
    UNVERIFIABLE = "UNVERIFIABLE"
    ERROR = "ERROR"  # request failed / could not be evaluated


class Query(BaseModel):
    """Normalized set of identifiers to research. Any subset may be provided."""

    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    domain: Optional[str] = None
    name: Optional[str] = None

    def normalized(self) -> "Query":
        # Single normalization layer so collectors + correlation agree on values.
        from .normalize import norm_domain, norm_email, norm_text, norm_username

        return Query(
            username=norm_username(self.username),
            email=norm_email(self.email),
            phone=norm_text(self.phone),
            domain=norm_domain(self.domain),
            name=norm_text(self.name),
        )

    def is_empty(self) -> bool:
        return not any(
            (self.username, self.email, self.phone, self.domain, self.name)
        )


class SiteRule(BaseModel):
    """One site's detection rule, modeled on the WhatsMyName (wmn-data) schema."""

    name: str
    uri_check: str  # URL template containing {account}
    uri_pretty: Optional[str] = None
    # error_type: status_code | message | response_url
    error_type: str = "status_code"
    error_msg: Optional[Any] = None  # string or list of strings
    error_code: Optional[int] = None
    error_url: Optional[str] = None
    cat: Optional[str] = None
    tags: list[str] = Field(default_factory=list)

    def url_for(self, account: str) -> str:
        return self.uri_check.replace("{account}", account)


class Evidence(BaseModel):
    """Snapshot of a single HTTP response, used by the verify layers."""

    url: str
    status: int
    final_url: str
    body_len: int
    fingerprint: str  # simhash hex of normalized body
    title: Optional[str] = None
    contains_query: bool = False
    elapsed_ms: int = 0
    error: Optional[str] = None
    # Non-None when the response was a bot-wall / WAF / JS-gate / rate-limit;
    # holds the human reason (e.g. "Cloudflare challenge"). Drives UNVERIFIABLE.
    blocked: Optional[str] = None


class Finding(BaseModel):
    """A single result, post-verification, ready for streaming/clustering/export."""

    source: str  # e.g. "username:GitHub", "email:gravatar"
    category: str  # username | email | phone | domain | name
    label: str  # human label, e.g. site name
    url: Optional[str] = None
    verdict: Verdict
    confidence: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    # Strong identity signals for clustering (e.g. {"gravatar_hash": "..."}).
    signals: dict[str, str] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_hit(self) -> bool:
        """Confirmed presence — drives correlation, counting, and change diffs.
        UNVERIFIABLE is deliberately excluded: it is not evidence of existence."""
        return self.verdict in (Verdict.FOUND, Verdict.UNCERTAIN)

    @property
    def is_notable(self) -> bool:
        """Worth showing to the user (a hit, or an honest 'couldn't tell')."""
        return self.verdict in (Verdict.FOUND, Verdict.UNCERTAIN, Verdict.UNVERIFIABLE)
