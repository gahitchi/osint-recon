"""Calibration tooling (Phase 5c): measure whether the confidence score is
*calibrated* (does 0.8 mean right ~80% of the time?) against ground-truth labels.

`metrics.py` is pure (reliability diagram / Brier / ECE / confusion / threshold
suggestion); `labels.py` loads the shipped fixture; `runner.py` drives the live
verify engine over the labels and reports — never auto-tuning thresholds.
"""

from . import metrics
from .labels import load_labels
from .metrics import Sample
from .runner import independence_impact, run_calibration

__all__ = ["metrics", "Sample", "load_labels", "run_calibration", "independence_impact"]
