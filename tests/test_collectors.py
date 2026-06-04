"""Offline tests for non-network collector logic and clustering."""

import phonenumbers

from recon.collectors.email import gravatar_hash
from recon.correlate.cluster import cluster
from recon.correlate.score import score_identity
from recon.models import Finding, Verdict


def test_gravatar_hash_is_md5_of_normalized_email():
    # Known MD5 from the Gravatar docs example.
    assert gravatar_hash("  MyEmailAddress@example.com ") == \
        "0bc83cb571cd1c50ba6f3e8a78ef1346"


def test_phone_parsing_offline():
    num = phonenumbers.parse("+14155552671", None)
    assert phonenumbers.is_valid_number(num)


def test_cluster_merges_on_shared_strong_signal():
    f1 = Finding(source="email:gravatar", category="email", label="Gravatar",
                 verdict=Verdict.FOUND, confidence=0.9,
                 signals={"gravatar_hash": "abc", "email": "a@b.com"})
    f2 = Finding(source="name:openalex", category="name", label="OpenAlex",
                 verdict=Verdict.FOUND, confidence=0.8,
                 signals={"email": "a@b.com"})
    f3 = Finding(source="username:GitHub", category="username", label="GitHub",
                 verdict=Verdict.FOUND, confidence=0.9,
                 signals={"username:github": "alice"})
    clusters = cluster([f1, f2, f3])
    # f1 & f2 share email -> one cluster; f3 separate -> 2 clusters total.
    assert len(clusters) == 2
    sizes = sorted(len(c.findings) for c in clusters)
    assert sizes == [1, 2]


def test_score_rewards_corroboration():
    strong = cluster([
        Finding(source="a", category="x", label="a", verdict=Verdict.FOUND,
                confidence=0.9, signals={"email": "e@x.com"}),
        Finding(source="b", category="x", label="b", verdict=Verdict.FOUND,
                confidence=0.9, signals={"email": "e@x.com"}),
    ])[0]
    weak = cluster([
        Finding(source="c", category="x", label="c", verdict=Verdict.UNCERTAIN,
                confidence=0.4),
    ])[0]
    assert score_identity(strong) > score_identity(weak)
