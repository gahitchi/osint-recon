"""Declarative correlation-rules engine (fires on the discovery graph).

Phase 4: turns the raw artifact graph into *insights* — same avatar across N
accounts, reused handle + breached email, broad subdomain footprint — via rules
expressed as data, not code. See `model.py` (schema), `engine.py` (evaluator),
`library.py` (built-ins + `RECON_RULES_FILE` loader).
"""

from .engine import evaluate
from .library import DEFAULT_RULES, load_rules, rule_catalogue
from .model import Clause, Rule, RuleHit, Severity

__all__ = [
    "evaluate", "load_rules", "rule_catalogue", "DEFAULT_RULES",
    "Rule", "Clause", "RuleHit", "Severity",
]
