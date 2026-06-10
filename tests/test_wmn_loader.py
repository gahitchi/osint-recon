"""The WhatsMyName schema translator + dataset loading."""

import json

from recon.collectors.username import _from_wmn, _is_wmn, load_sites


def test_detects_wmn_entries():
    assert _is_wmn({"name": "X", "uri_check": "u", "m_string": "nope"})
    assert _is_wmn({"name": "X", "uri_check": "u", "m_code": 404})
    # A native SiteRule entry (has error_type) is NOT treated as wmn.
    assert not _is_wmn({"name": "X", "uri_check": "u", "error_type": "status_code"})


def test_from_wmn_prefers_message_then_status():
    msg = _from_wmn({"name": "Foo", "uri_check": "https://foo/{account}",
                     "m_string": "User not found", "cat": "social"})
    assert msg["error_type"] == "message"
    assert msg["error_msg"] == "User not found"
    assert msg["tags"] == ["social"]

    code = _from_wmn({"name": "Bar", "uri_check": "https://bar/{account}", "m_code": 404})
    assert code["error_type"] == "status_code"
    assert code["error_code"] == 404


def test_load_sites_maps_wmn_and_filters_excluded(tmp_path):
    data = {"sites": [
        {"name": "Foo", "uri_check": "https://foo/{account}", "m_code": 404, "cat": "coding"},
        {"name": "Instagram", "uri_check": "https://instagram.com/{account}", "m_code": 404},
    ]}
    p = tmp_path / "wmn.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    rules = load_sites(str(p))
    names = {r.name for r in rules}
    assert "Foo" in names                 # wmn entry loaded + mapped
    assert "Instagram" not in names       # auth-walled platform excluded by name
    foo = next(r for r in rules if r.name == "Foo")
    assert foo.error_type == "status_code" and foo.error_code == 404
    assert foo.url_for("alice") == "https://foo/alice"
