"""Central configuration. Thresholds here control the precision/recall tradeoff
of the false-positive engine — tune them in one place."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    # --- HTTP ---
    user_agent: str = (
        "osint-recon/0.1 (+https://github.com/local/osint-recon; authorized research only)"
    )
    request_timeout: float = 12.0
    max_concurrency: int = 24
    per_host_min_interval: float = 0.5  # seconds between hits to the same host
    max_redirects: int = 5
    respect_robots: bool = True
    max_body_bytes: int = 512_000  # cap body we read/fingerprint

    # --- False-positive verdict thresholds (0..1) ---
    # If real response is at least this similar to the "absent" baseline body,
    # treat it as a soft-404 and reject.
    baseline_similarity_reject: float = 0.92
    # Confidence at/above which we emit FOUND.
    found_confidence: float = 0.75
    # Below found_confidence but at/above this -> UNCERTAIN (shown, flagged).
    uncertain_confidence: float = 0.40

    # Random control-probe username: prefix + this many random chars.
    control_probe_len: int = 18
    # Reproducibility: when true, the control-probe username is derived
    # deterministically from probe_seed (+ site), so a given input yields the
    # same baseline and thus the same verdicts across runs. (#8)
    deterministic: bool = bool(__import__("os").environ.get("RECON_DETERMINISTIC"))
    probe_seed: int = 1337

    # --- Collectors enabled by default (full automation) ---
    enabled_collectors: tuple[str, ...] = (
        "username",
        "email",
        "phone",
        "domain",
        "name",
    )

    # Sites/categories excluded by default (auth-walled / ToS-restricted).
    excluded_site_tags: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"instagram", "discord", "facebook", "twitter", "x", "linkedin", "snapchat"}
        )
    )

    # --- Paths ---
    sites_data_file: str = "data/sites.json"
    reports_dir: str = "reports"

    # --- Storage / scale (pluggable; local-first defaults) ---
    storage_dsn: str = "sqlite:///data/recon.db"  # set RECON_DB_DSN to a Postgres URL
    queue_backend: str = "local"  # local | arq
    cache_ttl_seconds: int = 6 * 3600
    breaker_fail_threshold: int = 4
    breaker_cooldown_seconds: int = 300

    # --- Correlation / entity resolution thresholds ---
    name_match_threshold: float = 0.92  # Jaro-Winkler (mirrors Specter)
    er_merge_threshold: float = 6.0  # summed match weight -> auto-merge
    er_review_threshold: float = 3.0  # summed match weight -> REVIEW (never silent)

    # --- Server ---
    host: str = "127.0.0.1"  # local-first: never bind publicly
    port: int = 8000


SETTINGS = Settings()
