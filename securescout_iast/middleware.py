import uuid
import logging
import traceback
from typing import Any
from urllib.parse import parse_qsl
from http.cookies import SimpleCookie

from securescout_iast.taint import (
    init_request_taint_registry,
    register_taint,
    register_endpoint,
    clear_thread_taint_registry,
    get_all_tainted_values,
    get_endpoint
)
from securescout_iast.reporter import queue_finding

logger = logging.getLogger("securescout_iast")


class SecureScoutIastMiddleware:
    """
    Pure ASGI Middleware that performs wire-level interception of query parameters,
    headers, cookies, and body inputs. Stores observed taint data in task-local ContextVars
    without modifying Starlette's Request objects or customer application types.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_headers: dict = {}
        body_chunks: list[bytes] = []
        body_complete = False

        # 1. Initialize context-isolated registry and request ID
        request_id = str(uuid.uuid4())
        scope["securescout_request_id"] = request_id
        init_request_taint_registry()

        # Register endpoint context
        endpoint = f"{scope.get('method', 'GET')} {scope.get('path', '/')}"
        register_endpoint(request_id, endpoint)

        try:
            # 2. Parse raw query string from scope
            query_bytes = scope.get("query_string", b"")
            try:
                query_string = query_bytes.decode("utf-8", errors="ignore")
                if query_string:
                    for key, val in parse_qsl(query_string, keep_blank_values=True):
                        if len(val) >= 6:
                            register_taint(val, source="query_param", field_name=key, request_id=request_id)
            except Exception as e:
                logger.debug(f"Failed to parse query string: {e}")

            # 3. Parse cookies and client headers from scope headers list
            for raw_key, raw_val in scope.get("headers", []):
                try:
                    key = raw_key.decode("latin-1").lower()
                    val = raw_val.decode("latin-1")
                    
                    if key == "cookie":
                        cookie = SimpleCookie()
                        cookie.load(val)
                        for c_key, morsel in cookie.items():
                            if len(morsel.value) >= 6:
                                register_taint(morsel.value, source="cookie", field_name=c_key, request_id=request_id)
                    elif key in {"referer", "user-agent", "x-forwarded-for"}:
                        if len(val) >= 6:
                            register_taint(val, source="header", field_name=key, request_id=request_id)
                except Exception as e:
                    logger.debug(f"Failed to parse header {raw_key}: {e}")

            # 4. Content-Length pre-check to prevent buffering huge bodies
            content_length = 0
            for rk, rv in scope.get("headers", []):
                if rk.decode("latin-1").lower() == "content-length":
                    try:
                        content_length = int(rv.decode("latin-1"))
                    except ValueError:
                        pass
                    break

            max_buffer_size = 1_000_000  # 1MB size limit
            should_buffer_body = content_length <= max_buffer_size

            body_bytes = bytearray()
            buffer_overflow = False

            # Wrap receive function to capture request body chunks safely
            async def wrapped_receive():
                nonlocal buffer_overflow
                message = await receive()
                if should_buffer_body and not buffer_overflow and message.get("type") == "http.request":
                    chunk = message.get("body", b"")
                    if chunk:
                        # Enforce hard cap during streaming (e.g. if Content-Length was missing or lying)
                        if len(body_bytes) + len(chunk) > max_buffer_size:
                            buffer_overflow = True
                            body_bytes.clear()  # Free memory immediately
                            logger.debug("Body size exceeded 1MB cap. Taint extraction disabled for this request.")
                        else:
                            body_bytes.extend(chunk)

                    # Trigger parsing only on the final chunk if no overflow occurred
                    if not message.get("more_body", False) and not buffer_overflow:
                        try:
                            # Extract Content-Type header from scope
                            content_type = ""
                            for rk, rv in scope.get("headers", []):
                                if rk.decode("latin-1").lower() == "content-type":
                                    content_type = rv.decode("latin-1")
                                    break
                            
                            if "application/json" in content_type:
                                import json
                                parsed_json = json.loads(body_bytes.decode("utf-8"))
                                _extract_json_taints(parsed_json, request_id)
                            elif "application/x-www-form-urlencoded" in content_type:
                                form_data = body_bytes.decode("utf-8")
                                for fk, fv in parse_qsl(form_data, keep_blank_values=True):
                                    if len(fv) >= 6:
                                        register_taint(fv, source="body", field_name=fk, request_id=request_id)
                        except Exception as e:
                            logger.debug(f"Failed to extract body taints: {e}")
                return message

            async def wrapped_send(message: dict) -> None:
                nonlocal response_headers, body_chunks, body_complete

                if message["type"] == "http.response.start":
                    # Capture headers so we can read content-type later
                    response_headers = {
                        k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in message.get("headers", [])
                    }
                    await send(message)

                elif message["type"] == "http.response.body":
                    chunk = message.get("body", b"")
                    more = message.get("more_body", False)
                    body_chunks.append(chunk)

                    if not more:
                        # Final chunk — run XSS check before releasing
                        try:
                            full_body = b"".join(body_chunks)
                            content_type = response_headers.get("content-type", "")
                            from securescout_iast.sinks.xss_sink import check_response_taint
                            hit = check_response_taint(full_body, content_type)
                            if hit:
                                from securescout_iast.redact import redact_tainted_value, redact_stack_trace
                                taint_meta = get_all_tainted_values().get(hit, {})
                                queue_finding(
                                    rule="xss_reflected",
                                    tainted_value=redact_tainted_value(hit),
                                    source=taint_meta.get("source", "unknown"),
                                    field_name=taint_meta.get("field_name", "unknown"),
                                    request_id=scope.get("securescout_request_id", request_id),
                                    query_snippet=redact_tainted_value(hit),
                                    stack_trace=redact_stack_trace([str(f) for f in traceback.extract_stack()]),
                                    endpoint=get_endpoint(),
                                )
                        except Exception:
                            pass  # fail-safe — never block the response

                        await send(message)
                    else:
                        await send(message)

                else:
                    await send(message)

            # Execute the ASGI application stack passing the wrapped receive and wrapped send
            await self.app(scope, wrapped_receive, wrapped_send)

        finally:
            # 5. Guaranteed cleanup of contextvars memory
            clear_thread_taint_registry()


def _extract_json_taints(data: Any, request_id: str, field_name: str = "") -> None:
    """Recursively walks parsed JSON payload elements to register string values >= 6 chars."""
    if isinstance(data, str):
        if len(data) >= 6:
            register_taint(data, source="body", field_name=field_name, request_id=request_id)
    elif isinstance(data, dict):
        for k, v in data.items():
            _extract_json_taints(v, request_id, field_name=str(k))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            _extract_json_taints(item, request_id, field_name=f"{field_name}[{idx}]")
