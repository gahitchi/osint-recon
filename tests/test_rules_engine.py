"""Phase-4 declarative correlation-rules engine: rules fire on the discovery
graph for real patterns, and don't fire on unrelated graphs."""

from recon.engine import _Edge
from recon.graph_models import Artifact, ArtifactType as AT
from recon.rules import Rule, evaluate, load_rules, rule_catalogue


def _ids(hits):
    return {h.rule_id for h in hits}


def test_email_in_breach_threshold():
    email = Artifact.make(AT.EMAIL, "torvalds@example.com")
    breach = Artifact.make(AT.BREACH, "AcmeLeak", parent=email,
                           source_module="breach", email="torvalds@example.com")
    hits = evaluate([email, breach], rules=load_rules())
    assert "email-in-breach" in _ids(hits)


def test_handle_reuse_breached_joins_on_handle():
    user = Artifact.make(AT.USERNAME, "torvalds")
    email = Artifact.make(AT.EMAIL, "torvalds@example.com")
    breach = Artifact.make(AT.BREACH, "AcmeLeak", parent=email,
                           source_module="breach", email="torvalds@example.com")
    hits = evaluate([user, email, breach], rules=load_rules())
    hit = next(h for h in hits if h.rule_id == "handle-reuse-breached")
    assert hit.severity == "high"
    assert hit.key == "torvalds"            # joined on the folded handle


def test_handle_reuse_does_not_fire_for_different_handles():
    user = Artifact.make(AT.USERNAME, "alice")
    email = Artifact.make(AT.EMAIL, "bob@example.com")
    breach = Artifact.make(AT.BREACH, "AcmeLeak", parent=email,
                           source_module="breach", email="bob@example.com")
    assert "handle-reuse-breached" not in _ids(evaluate([user, email, breach], rules=load_rules()))


def test_avatar_reuse_counts_distinct_parents_via_edges():
    # Engine dedup => ONE hash node with TWO incoming edges (two emails).
    e1 = Artifact.make(AT.EMAIL, "a@x.com")
    e2 = Artifact.make(AT.EMAIL, "b@y.com")
    h = Artifact.make(AT.HASH, "deadbeef", parent=e1, source_module="email")
    edges = [_Edge(e1.key, h.key, "email", {}), _Edge(e2.key, h.key, "email", {})]
    hits = evaluate([e1, e2, h], edges, rules=load_rules())
    assert "avatar-reuse" in _ids(hits)


def test_avatar_reuse_single_parent_does_not_fire():
    e1 = Artifact.make(AT.EMAIL, "a@x.com")
    h = Artifact.make(AT.HASH, "deadbeef", parent=e1, source_module="email")
    edges = [_Edge(e1.key, h.key, "email", {})]
    assert "avatar-reuse" not in _ids(evaluate([e1, h], edges, rules=load_rules()))


def test_handle_across_platforms_counts_distinct_platforms():
    seed = Artifact.make(AT.USERNAME, "torvalds")
    profiles = [
        Artifact.make(AT.ACCOUNT_PROFILE, u, parent=seed, source_module="username")
        for u in ("https://github.com/torvalds",
                  "https://twitter.com/torvalds",
                  "https://mastodon.social/@torvalds")
    ]
    hits = evaluate([seed, *profiles], rules=load_rules())
    assert "handle-across-platforms" in _ids(hits)


def test_thresholds_for_footprint_and_networks():
    dom = Artifact.make(AT.DOMAIN, "example.com")
    subs = [Artifact.make(AT.SUBDOMAIN, f"s{i}.example.com", parent=dom,
                          source_module="domain") for i in range(8)]
    asns = [Artifact.make(AT.ASN, f"AS{n}", parent=dom, source_module="asn")
            for n in (13335, 15169)]
    ids = _ids(evaluate([dom, *subs, *asns], rules=load_rules()))
    assert {"broad-subdomain-footprint", "multi-network-infra"} <= ids


def test_clean_graph_fires_nothing():
    arts = [Artifact.make(AT.DOMAIN, "example.com"),
            Artifact.make(AT.IP_ADDRESS, "93.184.216.34")]
    assert evaluate(arts, rules=load_rules()) == []


def test_user_rule_overrides_via_file(tmp_path, monkeypatch):
    rules_file = tmp_path / "rules.json"
    rules_file.write_text('[{"id":"email-in-breach","title":"X","severity":"low",'
                          '"kind":"threshold","match":[{"type":"breach"}],"min_count":99}]')
    monkeypatch.setenv("RECON_RULES_FILE", str(rules_file))
    # Built-in min_count=1 is overridden to 99, so a single breach no longer fires.
    email = Artifact.make(AT.EMAIL, "a@x.com")
    breach = Artifact.make(AT.BREACH, "L", parent=email, source_module="breach", email="a@x.com")
    assert "email-in-breach" not in _ids(evaluate([email, breach], rules=load_rules()))
    assert any(r.id == "email-in-breach" and r.min_count == 99 for r in load_rules())


def test_catalogue_lists_builtin_rules():
    cat = {r["id"] for r in rule_catalogue()}
    assert {"email-in-breach", "handle-reuse-breached", "avatar-reuse"} <= cat


def test_where_predicate_ops():
    # A bespoke rule using a data.* predicate with an operator.
    rule = Rule.from_dict({
        "id": "verified-profiles", "title": "t", "severity": "info",
        "kind": "threshold", "min_count": 1,
        "match": [{"type": "account_profile", "where": {"data.verified": {"eq": True}}}],
    })
    a = Artifact.make(AT.ACCOUNT_PROFILE, "https://x.com/u", verified=True)
    b = Artifact.make(AT.ACCOUNT_PROFILE, "https://x.com/v", verified=False)
    assert _ids(evaluate([a, b], rules=[rule])) == {"verified-profiles"}
