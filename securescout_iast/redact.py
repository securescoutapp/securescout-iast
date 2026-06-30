"""
Redaction helpers — strip sensitive data before transmitting findings to the backend.
Applied to: tainted_value, query_snippet, stack_trace entries.
"""
from __future__ import annotations

import hashlib
import re

# Matches SQL string literals: 'any content here'
_SQL_LITERAL_RE = re.compile(r"'[^']*'")

# Matches standalone integers ≥3 digits (potential IDs, SSNs, etc.)
_INT_LITERAL_RE = re.compile(r"\b\d{3,}\b")


def redact_tainted_value(value: str) -> str:
    """
    Returns a safe representation of a tainted value.
    Sends first 2 + last 2 chars with a SHA-256 hash prefix — enough to
    correlate findings without exposing the raw value.
    """
    if not isinstance(value, str):
        return "***"
    if len(value) <= 6:
        return "***"
    prefix = value[:2]
    suffix = value[-2:]
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{prefix}***{suffix} [sha256:{digest}]"


def redact_query_snippet(query: str, max_length: int = 500) -> str:
    """
    Strips SQL string literals and large integer values from query strings,
    then truncates to max_length.
    """
    if not isinstance(query, str):
        return ""
    redacted = _SQL_LITERAL_RE.sub("'***'", query)
    redacted = _INT_LITERAL_RE.sub("***", redacted)
    return redacted[:max_length]


def redact_stack_trace(stack: list[str]) -> list[str]:
    """
    Strips source line content from stack trace entries.
    Keeps file path and line number only — removes the actual code line.
    Input format: 'File "path", line N, in func\n    source_line'
    Output format: 'File "path", line N, in func'
    """
    result = []
    for entry in stack[:15]:  # hard cap at 15 frames
        # Keep only the first line of each frame (file/line/func), drop source line
        first_line = entry.split("\n")[0] if "\n" in entry else entry
        result.append(first_line)
    return result
