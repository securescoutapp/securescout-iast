import logging
import traceback
import sqlite3

from securescout_iast.taint import check_query_taint, get_endpoint

logger = logging.getLogger("securescout_iast")


class Sqlite3CursorWrapper:
    """Wrapper that delegates calls to a real sqlite3.Cursor and intercepts query executions."""
    def __init__(self, cursor, reporter_callback):
        self._cursor = cursor
        self._reporter_callback = reporter_callback

    def execute(self, query, parameters=None):
        try:
            if isinstance(query, str):
                match = check_query_taint(query)
                if match:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    self._reporter_callback(
                        rule="sql_injection",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query,
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )
        except Exception as e:
            logger.debug(f"sqlite3 execute hook error: {e}")

        if parameters is None:
            return self._cursor.execute(query)
        return self._cursor.execute(query, parameters)

    def executemany(self, query, seq_of_parameters):
        try:
            if isinstance(query, str):
                match = check_query_taint(query)
                if match:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    self._reporter_callback(
                        rule="sql_injection",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query,
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )
        except Exception as e:
            logger.debug(f"sqlite3 executemany hook error: {e}")

        return self._cursor.executemany(query, seq_of_parameters)

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)


class Sqlite3ConnectionWrapper:
    """Wrapper that delegates calls to a real sqlite3.Connection and wraps returned cursors."""
    def __init__(self, connection, reporter_callback):
        self._connection = connection
        self._reporter_callback = reporter_callback

    def cursor(self, *args, **kwargs):
        real_cursor = self._connection.cursor(*args, **kwargs)
        return Sqlite3CursorWrapper(real_cursor, self._reporter_callback)

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._connection.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def install_sqlite3_patch(reporter_callback) -> None:
    """Monkey-patches the sqlite3.connect module function to return wrapped connections."""
    _original_connect = sqlite3.connect

    def custom_connect(*args, **kwargs):
        real_conn = _original_connect(*args, **kwargs)
        return Sqlite3ConnectionWrapper(real_conn, reporter_callback)

    sqlite3.connect = custom_connect
    logger.info("Successfully installed sqlite3 wrapper patch.")
