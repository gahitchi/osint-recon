"""Core data models shared across collectors, the verify engine, and reporting."""

from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Verdict(str, enum.Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNCERTAIN = "UNCERTAIN"
    ERROR = "ERROR"  # request failed / could not be evaluated


class Query(BaseModel):
    """Normalized set of identifiers to research. Any subset may be provided."""

    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    domain: Optional[str] = None
    name: Optional[str] = None

    def normalized(self) -> "Query":
        def n(s: Optional[str]) -> Optional[str]:
            return s.strip() if isinstance(s, str) and s.strip() else None

        return Query(
            username=n(self.username),
            email=n(self.email).lower() if n(self.email) else None,
            phone=n(self.phone),
            domain=n(self.domain).lower() if n(self.domain) else None,
            name=n(self.name),
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
        return self.verdict in (Verdict.FOUND, Verdict.UNCERTAIN)
