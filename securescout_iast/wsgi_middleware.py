"""
SecureScout IAST — WSGI Middleware
PEP 3333 compliant. Works with Flask, Django, Pyramid, Falcon, and any WSGI server
(gunicorn, uwsgi, mod_wsgi). Thread-safe via contextvars.
"""
from __future__ import annotations

import io
import logging
import traceback
import urllib.parse
import uuid
from http.cookies import SimpleCookie
from typing import Callable, Iterable

from securescout_iast.taint import (
    init_request_taint_registry,
    register_taint,
    register_endpoint,
    clear_thread_taint_registry,
    get_all_tainted_values,
    get_endpoint,
)
from securescout_iast.sinks.xss_sink import check_response_taint
from securescout_iast.reporter import queue_finding

logger = logging.getLogger("securescout_iast")

_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1MB


def _extract_json_taints(data, request_id: str, field_name: str = "", depth: int = 0) -> None:
    """Recursively extract string values from JSON for taint registration."""
    if depth > 20:
        return
    if isinstance(data, dict):
        for k, v in data.items():
            _extract_json_taints(v, request_id, field_name=str(k), depth=depth + 1)
    elif isinstance(data, list):
        for item in data:
            _extract_json_taints(item, request_id, field_name=field_name, depth=depth + 1)
    elif isinstance(data, str) and len(data) >= 6:
        try:
            register_taint(data, source="body", field_name=field_name or "json", request_id=request_id)
        except Exception:
            pass


class SecureScoutWsgiMiddleware:
    """
    Wrap any WSGI application to enable SecureScout IAST runtime monitoring.

    Usage (Flask):
        from securescout_iast import SecureScoutWsgiMiddleware
        app.wsgi_app = SecureScoutWsgiMiddleware(app.wsgi_app)

    Usage (Django):
        # In wsgi.py, wrap get_wsgi_application()
        from securescout_iast import SecureScoutWsgiMiddleware
        application = SecureScoutWsgiMiddleware(get_wsgi_application())
    """

    def __init__(self, app: Callable) -> None:
        self.app = app

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        init_request_taint_registry()
        request_id = str(uuid.uuid4())
        should_clear = True

        try:
            self._extract_taints(environ, request_id)

            method = environ.get("REQUEST_METHOD", "GET")
            path = environ.get("PATH_INFO", "/")
            register_endpoint(request_id, f"{method} {path}")

            response_content_type: list[str] = [""]

            def wrapped_start_response(status: str, headers: list, exc_info=None):
                for name, value in headers:
                    if name.lower() == "content-type":
                        response_content_type[0] = value
                        break
                return start_response(status, headers, exc_info) if exc_info else start_response(status, headers)

            result = self.app(environ, wrapped_start_response)
            should_clear = False
            return _TaintCheckingIterator(
                result,
                content_type=response_content_type,
                request_id=request_id,
            )

        except Exception:
            # Fail-safe — never crash the customer app
            logger.debug("SecureScout WSGI middleware error", exc_info=True)
            return self.app(environ, start_response)

        finally:
            if should_clear:
                clear_thread_taint_registry()

    def _extract_taints(self, environ: dict, request_id: str) -> None:
        # Query string params
        qs = environ.get("QUERY_STRING", "")
        if qs:
            for field, values in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
                for v in values:
                    try:
                        register_taint(v, source="query_param", field_name=field, request_id=request_id)
                    except Exception:
                        pass

        # Cookies
        cookie_header = environ.get("HTTP_COOKIE", "")
        if cookie_header:
            try:
                cookie = SimpleCookie(cookie_header)
                for key, morsel in cookie.items():
                    if len(morsel.value) >= 6:
                        register_taint(morsel.value, source="cookie", field_name=key, request_id=request_id)
            except Exception:
                pass

        # Selected HTTP headers
        for header in ("HTTP_REFERER", "HTTP_USER_AGENT", "HTTP_X_FORWARDED_FOR"):
            val = environ.get(header, "")
            if val and len(val) >= 6:
                field = header[5:].lower()  # strip HTTP_ prefix
                try:
                    register_taint(val, source="header", field_name=field, request_id=request_id)
                except Exception:
                    pass

        # Request body — read full body but only taint-scan first _MAX_BODY_BYTES
        try:
            wsgi_input = environ.get("wsgi.input")
            if wsgi_input:
                full_body = wsgi_input.read()
                # Always restore the full body so the app receives it intact
                environ["wsgi.input"] = io.BytesIO(full_body)
                taint_body = full_body[:_MAX_BODY_BYTES]
                content_type = environ.get("CONTENT_TYPE", "")
                if "application/x-www-form-urlencoded" in content_type:
                    for field, values in urllib.parse.parse_qs(
                        taint_body.decode("utf-8", errors="replace"), keep_blank_values=True
                    ).items():
                        for v in values:
                            register_taint(v, source="body", field_name=field, request_id=request_id)
                elif "application/json" in content_type and taint_body:
                    try:
                        import json
                        parsed = json.loads(taint_body.decode("utf-8", errors="replace"))
                        _extract_json_taints(parsed, request_id)
                    except Exception:
                        pass
                # F23 fix — remove raw body blob registration entirely
        except Exception:
            pass


class _TaintCheckingIterator:
    """
    Buffers the WSGI response iterable, runs XSS check on full body,
    then yields chunks unchanged. Transparent to the WSGI server.
    """

    def __init__(self, iterable: Iterable[bytes], content_type: list[str], request_id: str) -> None:
        self._iterable = iterable
        self._content_type = content_type
        self._request_id = request_id
        self._chunks: list[bytes] = []
        self._checked = False

    def __iter__(self):
        try:
            for chunk in self._iterable:
                self._chunks.append(chunk)
                yield chunk
        finally:
            self._run_check()

    def _run_check(self) -> None:
        if self._checked:
            return
        self._checked = True
        try:
            full_body = b"".join(self._chunks)
            hit = check_response_taint(full_body, self._content_type[0])
            if hit:
                from securescout_iast.redact import redact_tainted_value, redact_stack_trace
                taint_meta = get_all_tainted_values().get(hit, {})
                queue_finding(
                    rule="xss_reflected",
                    tainted_value=redact_tainted_value(hit),
                    source=taint_meta.get("source", "unknown"),
                    field_name=taint_meta.get("field_name", "unknown"),
                    request_id=self._request_id,
                    query_snippet=redact_tainted_value(hit),
                    stack_trace=redact_stack_trace([str(f) for f in traceback.extract_stack()]),
                    endpoint=get_endpoint(),
                )
        except Exception:
            pass
        finally:
            clear_thread_taint_registry()

    def close(self) -> None:
        self._run_check()
        if hasattr(self._iterable, "close"):
            self._iterable.close()
