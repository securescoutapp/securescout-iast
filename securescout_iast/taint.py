import contextvars
from typing import Optional, List, Any, Dict, Set

# ContextVar storing a dictionary of: raw_tainted_string -> metadata_dict
_taint_registry: contextvars.ContextVar[Dict[str, dict]] = contextvars.ContextVar("securescout_iast_registry")

# ContextVar storing the HTTP endpoint string (e.g. "GET /api/users") for the request context
_endpoint_var: contextvars.ContextVar[str] = contextvars.ContextVar("securescout_iast_endpoint", default="unknown")


def init_request_taint_registry() -> Dict[str, dict]:
    """Initializes a fresh, task-isolated metadata dict for the current request context."""
    registry = {}
    _taint_registry.set(registry)
    return registry


def register_taint(value: str, source: str, field_name: str, request_id: str) -> None:
    """Registers a tainted string value and its provenance metadata."""
    if not value:
        return
    try:
        registry = _taint_registry.get()
    except LookupError:
        registry = init_request_taint_registry()
    
    registry[value] = {
        "source": source,
        "field_name": field_name,
        "request_id": request_id
    }


def get_taint_metadata(value: str) -> Optional[dict]:
    """Retrieves provenance metadata for a given tainted string value."""
    try:
        return _taint_registry.get().get(value)
    except LookupError:
        return None


def clear_thread_taint_registry() -> None:
    """Clears task-local metadata dict to release memory."""
    try:
        _taint_registry.get().clear()
    except Exception:
        pass


def check_query_taint(query: str) -> Optional[dict]:
    """
    Scans a query string for any registered tainted values.
    Returns the metadata dict of the matched taint if found.
    """
    try:
        registry = _taint_registry.get()
    except LookupError:
        return None

    for tainted_val, meta in registry.items():
        if tainted_val in query:
            return {
                "tainted_value": tainted_val,
                "source": meta["source"],
                "field_name": meta["field_name"],
                "request_id": meta["request_id"]
            }
    return None


def register_endpoint(request_id: str, endpoint: str) -> None:
    """Registers the HTTP endpoint (method + path) for the current request context."""
    _endpoint_var.set(endpoint)


def get_endpoint() -> str:
    """Retrieves the HTTP endpoint associated with the current request context."""
    try:
        return _endpoint_var.get()
    except LookupError:
        return "unknown"


class TaintedStr(str):
    """
    A subclass of str that carries provenance metadata indicating
    it originated from an untrusted source.
    """
    def __new__(
        cls,
        value: Any,
        source: Optional[str] = None,
        field_name: Optional[str] = None,
        request_id: Optional[str] = None
    ):
        obj = str.__new__(cls, value)
        obj.source = source
        obj.field_name = field_name
        obj.request_id = request_id
        return obj

    def _clone(self, new_value: str) -> "TaintedStr":
        """Clones the taint metadata to a new string value."""
        return TaintedStr(
            new_value,
            source=self.source,
            field_name=self.field_name,
            request_id=self.request_id
        )

    def __add__(self, other: Any) -> "TaintedStr":
        res = super().__add__(str(other))
        return self._clone(res)

    def __radd__(self, other: Any) -> "TaintedStr":
        res = str(other) + str(self)
        return self._clone(res)

    def __mod__(self, other: Any) -> "TaintedStr":
        res = super().__mod__(other)
        return self._clone(res)

    def __rmod__(self, other: Any) -> "TaintedStr":
        res = str(other) % str(self)
        return self._clone(res)

    def __getitem__(self, index: Any) -> "TaintedStr":
        res = super().__getitem__(index)
        return self._clone(res)

    def __format__(self, format_spec: str) -> str:
        res = super().__format__(format_spec)
        # Register in task-local storage if the tainted string is long enough
        # to avoid false positives on common short substrings (e.g. "id", "abc", "1")
        if len(self) >= 6:
            register_taint(str(self), source=self.source or "formatted", field_name=self.field_name or "unknown", request_id=self.request_id or "unknown")
        return res

    def replace(self, old: str, new: str, count: int = -1) -> "TaintedStr":
        res = super().replace(old, new, count)
        return self._clone(res)

    def split(self, sep: Optional[str] = None, maxsplit: int = -1) -> List["TaintedStr"]:
        res = super().split(sep, maxsplit)
        return [self._clone(item) for item in res]

    def strip(self, chars: Optional[str] = None) -> "TaintedStr":
        res = super().strip(chars)
        return self._clone(res)

    def lstrip(self, chars: Optional[str] = None) -> "TaintedStr":
        res = super().lstrip(chars)
        return self._clone(res)

    def rstrip(self, chars: Optional[str] = None) -> "TaintedStr":
        res = super().rstrip(chars)
        return self._clone(res)

    def lower(self) -> "TaintedStr":
        res = super().lower()
        return self._clone(res)

    def upper(self) -> "TaintedStr":
        res = super().upper()
        return self._clone(res)

    def join(self, iterable: Any) -> "TaintedStr":
        res = super().join(iterable)
        return self._clone(res)


def is_tainted(value: Any) -> bool:
    """Helper function to check if a value is a TaintedStr."""
    return isinstance(value, TaintedStr)
