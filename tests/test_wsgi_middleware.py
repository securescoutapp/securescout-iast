"""Unit tests for SecureScout WSGI middleware."""
import io
import html
import pytest
from securescout_iast.taint import _taint_registry
from securescout_iast.wsgi_middleware import SecureScoutWsgiMiddleware

# ── helpers ──────────────────────────────────────────────────────────────────

captured_findings: list[dict] = []

def _mock_queue_finding(**kwargs):
    captured_findings.append(kwargs)

def _make_environ(
    method="GET",
    path="/",
    query_string="",
    body=b"",
    content_type="text/html; charset=utf-8",
) -> dict:
    return {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": io.StringIO(),
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8000",
        "wsgi.url_scheme": "http",
    }

def _simple_html_app(taint_key="name"):
    """WSGI app that echoes query param unescaped in HTML."""
    def app(environ, start_response):
        import urllib.parse
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        val = qs.get(taint_key, [""])[0]
        body = f"<html><body>{val}</body></html>".encode()
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
    return app

def _safe_html_app():
    """WSGI app that escapes query param before echoing."""
    def app(environ, start_response):
        body = b"<html><body>Hello World</body></html>"  # no echo at all
        start_response("200 OK", [("Content-Type", "text/html"), ("Content-Length", str(len(body)))])
        return [body]
    return app

def _json_app():
    def app(environ, start_response):
        import urllib.parse
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        val = qs.get("name", [""])[0]
        body = f'{{"name": "{val}"}}'.encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [body]
    return app

def _run(wrapped_app, environ) -> bytes:
    """Drive the WSGI app and exhaust the iterator."""
    responses = []
    def start_response(status, headers, exc_info=None): pass
    result = wrapped_app(environ, start_response)
    for chunk in result:
        responses.append(chunk)
    if hasattr(result, "close"):
        result.close()
    return b"".join(responses)

# ── tests ─────────────────────────────────────────────────────────────────────

def setup_function():
    captured_findings.clear()

def test_xss_reflected_detected(monkeypatch):
    import securescout_iast.wsgi_middleware as wm
    import securescout_iast.reporter as rep
    monkeypatch.setattr(wm, "queue_finding", _mock_queue_finding)
    monkeypatch.setattr(rep, "queue_finding", _mock_queue_finding)

    payload = "<script>alert(1)</script>"
    app = SecureScoutWsgiMiddleware(_simple_html_app())
    environ = _make_environ(query_string=f"name={payload}")
    body = _run(app, environ)

    assert payload.encode() in body  # passthrough unchanged
    assert len(captured_findings) == 1
    assert captured_findings[0]["rule"] == "xss_reflected"
    assert captured_findings[0]["tainted_value"].startswith("<s***t> [sha256:")

def test_xss_escaped_not_flagged(monkeypatch):
    import securescout_iast.reporter as rep
    monkeypatch.setattr(rep, "queue_finding", _mock_queue_finding)

    payload = "<script>alert(1)</script>"
    app = SecureScoutWsgiMiddleware(_safe_html_app())
    environ = _make_environ(query_string=f"name={payload}")
    _run(app, environ)
    assert len(captured_findings) == 0

def test_json_response_skipped(monkeypatch):
    import securescout_iast.reporter as rep
    monkeypatch.setattr(rep, "queue_finding", _mock_queue_finding)

    payload = "<script>alert(1)</script>"
    app = SecureScoutWsgiMiddleware(_json_app())
    environ = _make_environ(query_string=f"name={payload}")
    _run(app, environ)
    assert len(captured_findings) == 0

def test_response_body_passthrough(monkeypatch):
    import securescout_iast.reporter as rep
    monkeypatch.setattr(rep, "queue_finding", _mock_queue_finding)

    app = SecureScoutWsgiMiddleware(_simple_html_app())
    environ = _make_environ(query_string="name=hello")
    body = _run(app, environ)
    assert b"hello" in body

def test_registry_isolation_between_requests(monkeypatch):
    """Taint from request 1 must not leak into request 2."""
    import securescout_iast.reporter as rep
    monkeypatch.setattr(rep, "queue_finding", _mock_queue_finding)

    payload = "<script>alert(1)</script>"
    app = SecureScoutWsgiMiddleware(_safe_html_app())

    # Request 1 — with tainted payload, escaped app → no finding
    _run(app, _make_environ(query_string=f"name={payload}"))
    captured_findings.clear()

    # Request 2 — clean input, verify registry is fresh
    _run(app, _make_environ(query_string="name=clean"))
    assert len(captured_findings) == 0
