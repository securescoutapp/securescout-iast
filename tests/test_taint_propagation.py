import sys
import types
import pytest
import contextvars

from securescout_iast.taint import (
    TaintedStr,
    register_taint,
    check_query_taint,
    init_request_taint_registry,
    get_endpoint,
    register_endpoint
)
from securescout_iast.patches.psycopg2_patch import install_psycopg2_patch


def test_tainted_str_propagation():
    """Verifies that TaintedStr propagates its type and metadata through common string operations."""
    t = TaintedStr("O-Malley", source="query_param", field_name="username", request_id="req-123")
    
    # Concatenation (+)
    res_add = "SELECT * FROM users WHERE name = '" + t + "'"
    assert isinstance(res_add, TaintedStr)
    assert res_add.source == "query_param"
    assert res_add.field_name == "username"
    assert res_add.request_id == "req-123"

    # Reflected Concat
    res_radd = t + " LIMIT 1"
    assert isinstance(res_radd, TaintedStr)

    # Replace
    res_rep = t.replace("O-", "O")
    assert isinstance(res_rep, TaintedStr)
    assert res_rep == "OMalley"

    # Strip
    t_padded = TaintedStr("  O-Malley  ", source="query_param", field_name="username", request_id="req-123")
    res_strip = t_padded.strip()
    assert isinstance(res_strip, TaintedStr)
    assert res_strip == "O-Malley"

    # Slicing (__getitem__)
    res_slice = t[0:3]
    assert isinstance(res_slice, TaintedStr)
    assert res_slice == "O-M"

    # Modulo format (%)
    res_mod = "SELECT * FROM users WHERE name = '%s'" % t
    assert isinstance(res_mod, TaintedStr)
    assert "O-Malley" in res_mod


def test_registry_matching_and_isolation():
    """Verifies that register_taint and check_query_taint are context-isolated."""
    # 1. Simulate Request A
    ctx_a = contextvars.copy_context()
    def run_a():
        init_request_taint_registry()
        register_taint("O-Malley", source="query_param", field_name="name", request_id="a")
        
        # Match expected
        match = check_query_taint("SELECT * FROM users WHERE name = 'O-Malley'")
        assert match is not None
        assert match["request_id"] == "a"
        
        # Clean query
        assert check_query_taint("SELECT * FROM users WHERE name = %s") is None
        
    ctx_a.run(run_a)

    # 2. Simulate Request B (should be isolated from Request A)
    ctx_b = contextvars.copy_context()
    def run_b():
        init_request_taint_registry()
        # Should not see Request A's taint
        assert check_query_taint("SELECT * FROM users WHERE name = 'O-Malley'") is None
        
        register_taint("admin_user", source="body", field_name="role", request_id="b")
        match = check_query_taint("UPDATE users SET role = 'admin_user'")
        assert match is not None
        assert match["request_id"] == "b"
        
    ctx_b.run(run_b)


def test_psycopg2_driver_mock_patching():
    """Mocks psycopg2 class structures and tests executing the patcher pipeline."""
    # 1. Construct a mock psycopg2 module
    mock_psycopg2 = types.ModuleType("psycopg2")
    mock_psycopg2.extensions = types.ModuleType("psycopg2.extensions")
    
    class DummyCursor:
        def execute(self, query, vars=None):
            return "executed"
            
        def executemany(self, query, vars_list):
            return "executed many"

    class DummyConnection:
        def cursor(self, *args, **kwargs):
            return DummyCursor()

    mock_psycopg2.connect = lambda *args, **kwargs: DummyConnection()
    mock_psycopg2.extensions.cursor = DummyCursor
    sys.modules["psycopg2"] = mock_psycopg2
    sys.modules["psycopg2.extensions"] = mock_psycopg2.extensions

    # 2. Install the patch
    reporter_calls = []
    def dummy_reporter(**kwargs):
        reporter_calls.append(kwargs)

    install_psycopg2_patch(dummy_reporter)

    # 3. Simulate context request
    ctx = contextvars.copy_context()
    def run_test():
        init_request_taint_registry()
        register_endpoint("req-789", "POST /api/login")
        register_taint("compromised_value", source="query_param", field_name="id", request_id="req-789")

        conn = mock_psycopg2.connect()
        cursor = conn.cursor()

        # Vulnerable call: concatenated tainted string
        cursor.execute("SELECT * FROM items WHERE id = 'compromised_value'")
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection"
        assert reporter_calls[0]["tainted_value"] == "compromised_value"
        assert reporter_calls[0]["endpoint"] == "POST /api/login"
        assert reporter_calls[0]["source"] == "query_param"

        # Safe call: parameterized query now triggers sql_injection_taint_flow
        reporter_calls.clear()
        cursor.execute("SELECT * FROM items WHERE id = %s", ("compromised_value",))
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "compromised_value"

    ctx.run(run_test)

    # Clean up mock from sys.modules
    sys.modules.pop("psycopg2", None)
    sys.modules.pop("psycopg2.extensions", None)
