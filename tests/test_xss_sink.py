"""Tests for XSS reflected taint sink."""
import pytest
from securescout_iast.taint import register_taint, _taint_registry
from securescout_iast.sinks.xss_sink import check_response_taint


def _seed_registry(values: dict):
    """Prime the ContextVar registry for the current sync context."""
    _taint_registry.set(values)


# --- content-type guard ---

def test_json_response_skipped():
    _seed_registry({"<script>alert(1)</script>": {"source": "query"}})
    assert check_response_taint(b'{"x":"<script>alert(1)</script>"}', "application/json") is None


def test_plain_text_skipped():
    _seed_registry({"hello": {"source": "query"}})
    assert check_response_taint(b"hello world", "text/plain") is None


# --- reflected XSS hit ---

def test_reflected_xss_detected():
    payload = '<script>alert("xss")</script>'
    _seed_registry({payload: {"source": "query"}})
    body = f"<html><body>{payload}</body></html>".encode()
    result = check_response_taint(body, "text/html")
    assert result == payload


# --- escaped value = safe ---

def test_escaped_value_not_flagged():
    import html
    payload = '<script>alert(1)</script>'
    escaped = html.escape(payload)
    _seed_registry({payload: {"source": "query"}})
    body = f"<html><body>{escaped}</body></html>".encode()
    assert check_response_taint(body, "text/html") is None


# --- empty / short values skipped ---

def test_short_taint_skipped():
    _seed_registry({"x": {"source": "query"}})
    assert check_response_taint(b"<html>x</html>", "text/html") is None


# --- clean response ---

def test_clean_html_no_finding():
    _seed_registry({"safe_value_not_in_body": {"source": "query"}})
    assert check_response_taint(b"<html><body>Hello world</body></html>", "text/html") is None


# --- xhtml content type ---

def test_xhtml_content_type_fires():
    payload = "<img src=x onerror=alert(1)>"
    _seed_registry({payload: {"source": "body"}})
    body = f"<html>{payload}</html>".encode()
    assert check_response_taint(body, "application/xhtml+xml") == payload
