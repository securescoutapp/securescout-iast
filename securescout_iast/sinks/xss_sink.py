"""
XSS reflected sink — checks whether any tainted request value
appears unescaped in an outgoing HTML response body.
"""
from __future__ import annotations

import html
from typing import Optional

from securescout_iast.taint import get_all_tainted_values

_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def check_response_taint(body: bytes, content_type: str) -> Optional[str]:
    """
    Returns the first tainted value found unescaped in *body*, or None.

    Only fires for HTML content types — JSON/plain responses are skipped.
    """
    ct = content_type.lower().split(";")[0].strip()
    if ct not in _HTML_CONTENT_TYPES:
        return None

    try:
        decoded = body.decode("utf-8", errors="replace")
    except Exception:
        return None

    tainted = get_all_tainted_values()
    for raw_value in tainted:
        if not isinstance(raw_value, str) or len(raw_value) < 2:
            continue
        # Fire if raw unescaped value appears anywhere in the body.
        # Drop the "escaped form not present" clause — if raw is present, it's a finding
        # regardless of whether an escaped form also appears elsewhere in the document.
        if raw_value in decoded:
            return raw_value

    return None
