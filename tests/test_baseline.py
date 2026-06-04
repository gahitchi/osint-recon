from recon.verify import similarity
from recon.verify.baseline import random_absent_account


def test_random_absent_account_is_unlikely():
    a = random_absent_account()
    b = random_absent_account()
    assert a != b
    assert a.startswith("zz")
    assert len(a) >= 18


def test_identical_bodies_are_maximally_similar():
    fp = similarity.fingerprint_hex("<html><body>hello world foo bar baz</body></html>")
    assert similarity.similarity_hex(fp, fp) == 1.0


def test_different_bodies_are_dissimilar():
    a = similarity.fingerprint_hex(
        "<html><body>alice profile 412 followers repos dotfiles</body></html>"
    )
    b = similarity.fingerprint_hex(
        "<html><body>page not found sorry try the home page help</body></html>"
    )
    assert similarity.similarity_hex(a, b) < 0.85


def test_normalize_strips_scripts_and_volatile_tokens():
    html = "<html><script>var x=1</script><body>Hi csrf_token=abcdef1234567890</body></html>"
    norm = similarity.normalize(html)
    assert "var x" not in norm
    assert "abcdef1234567890" not in norm
    assert "hi" in norm
