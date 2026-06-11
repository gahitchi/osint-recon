"""Ground-truth labels for calibration.

A small curated set of known-present / known-absent (account, site) pairs ships
in `data/calibration_labels.json`; point `RECON_CALIBRATION_FILE` at your own to
extend it. The control-probe baselines the verify engine already generates are
known-*negatives* by construction and can be harvested for free (runner.py), so
the shipped fixture mainly needs a handful of confirmed positives.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_DEFAULT = "data/calibration_labels.json"


def labels_file() -> Path:
    env = os.environ.get("RECON_CALIBRATION_FILE")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / _DEFAULT


def load_labels() -> list[dict]:
    """Each row: {category, account, site, present}. Returns [] if the file is
    missing (calibration then has nothing to do, which the runner reports)."""
    p = labels_file()
    if not p.exists():
        return []
    raw = json.loads(p.read_text(encoding="utf-8"))
    return raw.get("labels", raw) if isinstance(raw, (dict, list)) else []
