import logging
import traceback

from securescout_iast.taint import check_query_taint, check_params_taint, get_endpoint

logger = logging.getLogger("securescout_iast")

_reporter_callback = None


class Psycopg2CursorWrapper:
    def __init__(self, original_cursor):
        self._original_cursor = original_cursor

    def __getattr__(self, name):
        return getattr(self._original_cursor, name)

    def __enter__(self):
        self._original_cursor.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._original_cursor.__exit__(exc_type, exc_val, exc_tb)

    def execute(self, query, vars=None):
        try:
            query_str = query
            if isinstance(query, bytes):
                query_str = query.decode("utf-8", errors="ignore")
            
            match = None
            if isinstance(query_str, str):
                match = check_query_taint(query_str)
                if match and _reporter_callback:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    _reporter_callback(
                        rule="sql_injection",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query_str,
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )

            # F02 fix — also inspect bind parameters for tainted values
            if not match and vars is not None:
                match = check_params_taint(vars if isinstance(vars, (list, tuple, dict)) else (vars,))
                if match and _reporter_callback:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    _reporter_callback(
                        rule="sql_injection_taint_flow",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query_str[:200],
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )
        except Exception as e:
            logger.debug(f"psycopg2 execute hook error: {e}")
        
        return self._original_cursor.execute(query, vars)

    def executemany(self, query, vars_list):
        try:
            query_str = query
            if isinstance(query, bytes):
                query_str = query.decode("utf-8", errors="ignore")
            
            match = None
            if isinstance(query_str, str):
                match = check_query_taint(query_str)
                if match and _reporter_callback:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    _reporter_callback(
                        rule="sql_injection",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query_str,
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )

            # F02 fix — also inspect bind parameters for tainted values
            if not match and vars_list:
                for row in vars_list:
                    match = check_params_taint(row if isinstance(row, (list, tuple, dict)) else (row,))
                    if match:
                        break
                if match and _reporter_callback:
                    stack = [
                        f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                        for f in traceback.extract_stack()
                        if "securescout_iast" not in f.filename
                    ]
                    _reporter_callback(
                        rule="sql_injection_taint_flow",
                        tainted_value=match["tainted_value"],
                        source=match["source"],
                        field_name=match["field_name"],
                        request_id=match["request_id"],
                        query_snippet=query_str[:200],
                        stack_trace=stack,
                        endpoint=get_endpoint()
                    )
        except Exception as e:
            logger.debug(f"psycopg2 executemany hook error: {e}")
        
        return self._original_cursor.executemany(query, vars_list)


class Psycopg2ConnectionWrapper:
    def __init__(self, original_conn):
        self._original_conn = original_conn

    def __getattr__(self, name):
        return getattr(self._original_conn, name)

    def __enter__(self):
        self._original_conn.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._original_conn.__exit__(exc_type, exc_val, exc_tb)

    def cursor(self, *args, **kwargs):
        cursor_obj = self._original_conn.cursor(*args, **kwargs)
        return Psycopg2CursorWrapper(cursor_obj)


def install_psycopg2_patch(reporter_callback) -> None:
    """Monkey-patches psycopg2.connect to intercept query executions."""
    global _reporter_callback
    _reporter_callback = reporter_callback
    try:
        import psycopg2
        
        if not hasattr(psycopg2.connect, "_is_securescout_patch"):
            original = psycopg2.connect

            def custom_connect(*args, **kwargs):
                conn = original(*args, **kwargs)
                return Psycopg2ConnectionWrapper(conn)

            custom_connect._is_securescout_patch = True
            psycopg2.connect = custom_connect
            logger.info("Successfully patched psycopg2 connect constructor.")
    except ImportError:
        logger.debug("psycopg2 driver not found. Skipping patch.")
