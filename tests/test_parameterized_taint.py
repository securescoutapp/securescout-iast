import sys
import types
import pytest
import sqlite3
import contextvars
from securescout_iast.taint import (
    TaintedStr,
    register_taint,
    init_request_taint_registry,
    register_endpoint
)
from securescout_iast.patches.psycopg2_patch import install_psycopg2_patch
from securescout_iast.patches.asyncpg_patch import install_asyncpg_patch
from securescout_iast.patches.sqlite3_patch import install_sqlite3_patch

def test_psycopg2_parameterized_taint():
    """psycopg2 mock: tainted value in bind params -> sql_injection_taint_flow fired"""
    # 1. Mock psycopg2
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

    # 3. Run test in isolated context
    ctx = contextvars.copy_context()
    def run_test():
        init_request_taint_registry()
        register_endpoint("req-psycopg2", "POST /api/login")
        register_taint("tainted_password", source="body", field_name="password", request_id="req-psycopg2")

        conn = mock_psycopg2.connect()
        cursor = conn.cursor()

        # Parameterized query with tainted value in vars
        cursor.execute("SELECT * FROM users WHERE password = %s", ("tainted_password",))
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "tainted_password"
        assert reporter_calls[0]["source"] == "body"

        # clean parameterized query (untainted value) -> no finding
        reporter_calls.clear()
        cursor.execute("SELECT * FROM users WHERE password = %s", ("clean_password",))
        assert len(reporter_calls) == 0

        # executemany with tainted value in list of tuples
        reporter_calls.clear()
        cursor.executemany("INSERT INTO audit (val) VALUES (%s)", [("clean_val",), ("tainted_password",)])
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "tainted_password"

    ctx.run(run_test)
    sys.modules.pop("psycopg2", None)
    sys.modules.pop("psycopg2.extensions", None)

def test_asyncpg_parameterized_taint():
    """asyncpg mock: tainted value in args -> finding fired"""
    # Reset asyncpg patch state before test:
    import securescout_iast.patches.asyncpg_patch as ap
    ap._original_execute = None
    ap._reporter_callback = None

    # 1. Mock asyncpg.connection
    mock_asyncpg = types.ModuleType("asyncpg")
    mock_asyncpg_connection = types.ModuleType("asyncpg.connection")
    mock_asyncpg.connection = mock_asyncpg_connection
    sys.modules["asyncpg"] = mock_asyncpg
    sys.modules["asyncpg.connection"] = mock_asyncpg_connection

    class DummyConnectionClass:
        async def execute(self, query, *args, **kwargs):
            return "executed"
        async def fetch(self, query, *args, **kwargs):
            return "fetched"
        async def fetchrow(self, query, *args, **kwargs):
            return "fetched row"
        async def fetchval(self, query, *args, **kwargs):
            return "fetched val"

    mock_asyncpg_connection.Connection = DummyConnectionClass

    reporter_calls = []
    def dummy_reporter(**kwargs):
        reporter_calls.append(kwargs)

    install_asyncpg_patch(dummy_reporter)

    async def run_test():
        init_request_taint_registry()
        register_endpoint("req-asyncpg", "POST /api/search")
        register_taint("tainted_search", source="query_param", field_name="q", request_id="req-asyncpg")

        conn = DummyConnectionClass()

        # execute with tainted arg
        await conn.execute("SELECT * FROM items WHERE name = $1", "tainted_search")
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "tainted_search"

        # clean call
        reporter_calls.clear()
        await conn.execute("SELECT * FROM items WHERE name = $1", "clean_search")
        assert len(reporter_calls) == 0

    # Execute async test
    import asyncio
    asyncio.run(run_test())

    sys.modules.pop("asyncpg", None)
    sys.modules.pop("asyncpg.connection", None)

def test_sqlite3_parameterized_taint_and_idempotency():
    """sqlite3: tainted value in parameters tuple -> finding fired, clean parameterized -> no finding, and F14 idempotency test"""
    # 1. Verify idempotency: install_sqlite3_patch called twice -> no double wrap
    reporter_calls = []
    def dummy_reporter(**kwargs):
        reporter_calls.append(kwargs)

    original_connect = sqlite3.connect

    # Create a fresh mock connect function that delegates to original_connect
    def fresh_connect(*args, **kwargs):
        return original_connect(*args, **kwargs)

    sqlite3.connect = fresh_connect

    # Patch first time
    install_sqlite3_patch(dummy_reporter)
    first_connect = sqlite3.connect
    assert first_connect != fresh_connect
    assert getattr(first_connect, "_is_securescout_patch", False) is True

    # Call it again
    install_sqlite3_patch(dummy_reporter)
    second_connect = sqlite3.connect
    # Should not double patch/wrap
    assert second_connect == first_connect

    # 2. Run test in isolated context
    ctx = contextvars.copy_context()
    def run_test():
        init_request_taint_registry()
        register_endpoint("req-sqlite3", "GET /api/details")
        register_taint("tainted_id", source="query_param", field_name="id", request_id="req-sqlite3")

        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()

        # Setup table first (executemany requires DML like INSERT)
        cursor.execute("CREATE TABLE t (val TEXT)")

        # Parameterized query with tainted value in parameters
        cursor.execute("INSERT INTO t VALUES (?)", ("tainted_id",))
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "tainted_id"

        # Clean parameterized query -> no finding
        reporter_calls.clear()
        cursor.execute("INSERT INTO t VALUES (?)", ("clean_id",))
        assert len(reporter_calls) == 0

        # executemany with tainted value in sequence of parameters
        reporter_calls.clear()
        cursor.executemany("INSERT INTO t VALUES (?)", [("clean_val1",), ("tainted_id",)])
        assert len(reporter_calls) == 1
        assert reporter_calls[0]["rule"] == "sql_injection_taint_flow"
        assert reporter_calls[0]["tainted_value"] == "tainted_id"

    ctx.run(run_test)
    # Restore original connect
    sqlite3.connect = original_connect
