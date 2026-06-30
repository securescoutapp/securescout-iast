import logging
import traceback
from typing import Any

from securescout_iast.taint import check_query_taint, check_params_taint, get_endpoint

logger = logging.getLogger("securescout_iast")

_original_execute = None
_original_fetch = None
_original_fetchrow = None
_original_fetchval = None
_reporter_callback = None


def install_asyncpg_patch(reporter_callback) -> None:
    """Monkey-patches asyncpg connection queries to inspect query strings."""
    global _original_execute, _original_fetch, _original_fetchrow, _original_fetchval, _reporter_callback
    _reporter_callback = reporter_callback
    try:
        import asyncpg.connection

        if _original_execute is None:
            _original_execute = asyncpg.connection.Connection.execute
            _original_fetch = asyncpg.connection.Connection.fetch
            _original_fetchrow = asyncpg.connection.Connection.fetchrow
            _original_fetchval = asyncpg.connection.Connection.fetchval

            def _inspect_query(query: Any, args=None) -> None:
                try:
                    query_str = query
                    # If query is a PreparedStatement object, get its raw query text
                    if hasattr(query, "get_query"):
                        query_str = query.get_query()
                    
                    match = None
                    if isinstance(query_str, str):
                        match = check_query_taint(query_str)
                    
                    # F02 fix — inspect bind args for tainted values
                    if not match and args:
                        match = check_params_taint(args)
                        rule = "sql_injection_taint_flow"
                    else:
                        rule = "sql_injection"

                    if match and _reporter_callback:
                        stack = [
                            f"File \"{f.filename}\", line {f.lineno}, in {f.name}\n    {f.line}"
                            for f in traceback.extract_stack()
                            if "securescout_iast" not in f.filename
                        ]
                        _reporter_callback(
                            rule=rule,
                            tainted_value=match["tainted_value"],
                            source=match["source"],
                            field_name=match["field_name"],
                            request_id=match["request_id"],
                            query_snippet=query_str[:200] if isinstance(query_str, str) else "",
                            stack_trace=stack,
                            endpoint=get_endpoint()
                        )
                except Exception as e:
                    logger.debug(f"asyncpg query hook error: {e}")

            async def custom_execute(self, query, *args, **kwargs):
                _inspect_query(query, args=args)
                return await _original_execute(self, query, *args, **kwargs)

            async def custom_fetch(self, query, *args, **kwargs):
                _inspect_query(query, args=args)
                return await _original_fetch(self, query, *args, **kwargs)

            async def custom_fetchrow(self, query, *args, **kwargs):
                _inspect_query(query, args=args)
                return await _original_fetchrow(self, query, *args, **kwargs)

            async def custom_fetchval(self, query, *args, **kwargs):
                _inspect_query(query, args=args)
                return await _original_fetchval(self, query, *args, **kwargs)

            asyncpg.connection.Connection.execute = custom_execute
            asyncpg.connection.Connection.fetch = custom_fetch
            asyncpg.connection.Connection.fetchrow = custom_fetchrow
            asyncpg.connection.Connection.fetchval = custom_fetchval
            logger.info("Successfully patched asyncpg driver.")

    except ImportError:
        logger.debug("asyncpg driver not found. Skipping patch.")
