import logging
import threading
from securescout_iast.config import DEFAULT_BACKEND_URL
from securescout_iast.reporter import init_reporter, send_heartbeat, queue_finding
from securescout_iast.patches.psycopg2_patch import install_psycopg2_patch
from securescout_iast.patches.asyncpg_patch import install_asyncpg_patch
from securescout_iast.middleware import SecureScoutIastMiddleware

# Expose the ASGI middleware class and the init entrypoint
__all__ = ["SecureScoutIastMiddleware", "init"]

logger = logging.getLogger("securescout_iast")
_initialized = False


def init(
    api_key: str,
    project_id: str,
    backend_url: str = DEFAULT_BACKEND_URL,
    framework: str = "fastapi"
) -> None:
    """
    Initializes the SecureScout IAST runtime monitoring agent.
    Safely monkey-patches database connection libraries and spawns background telemetry loops.
    Guarantees no exception propagation to avoid interrupting customer application startup.
    """
    global _initialized
    if _initialized:
        logger.warning("SecureScout IAST agent is already initialized. Skipping setup.")
        return

    try:
        # Check inputs and degrade to no-op on missing parameters without raising ValueErrors
        if not api_key:
            logger.error("SecureScout IAST initialization aborted: API Key must not be empty.")
            return
        if not project_id:
            logger.error("SecureScout IAST initialization aborted: Project ID must not be empty.")
            return

        # 1. Initialize background telemetry batch reporter daemon
        init_reporter(api_key=api_key, project_id=project_id, backend_url=backend_url)

        # 2. Inject database driver interception monkey-patches
        install_psycopg2_patch(queue_finding)
        install_asyncpg_patch(queue_finding)

        # 3. Transmit connection heartbeat on a background thread to prevent blocking boot probes
        threading.Thread(
            target=send_heartbeat,
            args=(framework,),
            daemon=True
        ).start()

        _initialized = True
        logger.info("SecureScout IAST agent initialized successfully.")

    except Exception as e:
        # Guarantee absolute fail-safety for the customer app on startup
        logger.error(f"Failed to initialize SecureScout IAST agent: {e}", exc_info=True)
