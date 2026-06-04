"""Run provenance for reproducibility (#8).

Stamps every report with the tool version, the exact detection-dataset hash, key
dependency versions, and whether the run was deterministic — so a result can be
traced to the precise inputs that produced it.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path

from . import __version__
from .config import SETTINGS

_TRACKED = ("httpx", "sqlalchemy", "jellyfish", "phonenumbers", "dnspython", "fastapi")


@lru_cache(maxsize=1)
def sites_dataset_hash() -> str:
    root = Path(__file__).resolve().parents[2]
    p = root / SETTINGS.sites_data_file
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    except OSError:
        return "unknown"


def _ver(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except Exception:
        return "unknown"


def provenance() -> dict:
    return {
        "tool_version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "deterministic": SETTINGS.deterministic,
        "probe_seed": SETTINGS.probe_seed if SETTINGS.deterministic else None,
        "sites_dataset_sha256": sites_dataset_hash(),
        "thresholds": {
            "baseline_similarity_reject": SETTINGS.baseline_similarity_reject,
            "found_confidence": SETTINGS.found_confidence,
            "uncertain_confidence": SETTINGS.uncertain_confidence,
            "er_merge_threshold": SETTINGS.er_merge_threshold,
            "er_review_threshold": SETTINGS.er_review_threshold,
        },
        "dependencies": {pkg: _ver(pkg) for pkg in _TRACKED},
        "argv": " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "",
    }
