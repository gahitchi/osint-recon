"""Modules: the event-driven units of the recursive engine.

A Module declares which ArtifactTypes it `consumes` and `produces`. The engine
dispatches each discovered artifact to every module that accepts it; modules
emit Findings (evidence) and new Artifacts (pivots) back into the graph.

This generalizes the older one-collector-per-Query-field design in
`connectors/` into a recursive graph traversal, while reusing the same
resilience primitives (cache + circuit breaker + reliability) from
`connectors/cache.py`.
"""
