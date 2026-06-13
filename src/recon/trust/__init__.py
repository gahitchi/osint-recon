"""Trust layer: machinery that makes the confidence score *trustworthy* rather
than merely sophisticated — source-independence tracking (Phase 5a) and, later,
calibration and analytics.
"""

from .independence import (
    class_of,
    corroboration,
    independence_breadth,
    independent_classes,
)

__all__ = [
    "class_of",
    "independent_classes",
    "independence_breadth",
    "corroboration",
]
