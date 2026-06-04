"""Normalization layer: consistent identity fields, no duplicate-by-format."""

from recon.models import Query
from recon import normalize as nz


def test_username_strips_at_and_url():
    assert nz.norm_username("@Alice") == "alice"
    assert nz.norm_username("https://github.com/Alice/") == "alice"


def test_fold_handle_for_cross_platform_match():
    # "a.b_c" and "abc" are the same handle on platforms that ignore separators.
    assert nz.fold_handle("A.B_C") == "abc"


def test_email_and_domain():
    assert nz.norm_email("  Bob@Example.COM ") == "bob@example.com"
    assert nz.norm_domain("https://WWW.Example.com/path") == "example.com"


def test_url_canonicalization():
    a = nz.norm_url("http://www.Example.com/Profile/")
    b = nz.norm_url("https://example.com/Profile")
    assert a.split("://", 1)[1] == b.split("://", 1)[1]  # same host+path


def test_platform_aliases():
    assert nz.canonical_platform("X") == "twitter"
    assert nz.canonical_platform("Docker Hub") == "dockerhub"


def test_query_normalized_uses_layer():
    q = Query(username="@Torvalds", email="LT@Kernel.ORG", domain="WWW.Kernel.org").normalized()
    assert q.username == "torvalds"
    assert q.email == "lt@kernel.org"
    assert q.domain == "kernel.org"
