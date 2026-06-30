import sys
import queue
import threading
import time
import json
import logging
import urllib.request
from typing import List, Optional

logger = logging.getLogger("securescout_iast")

# Enforce a hard queue cap to prevent memory leaks during backend outages
_finding_queue: queue.Queue = queue.Queue(maxsize=500)
_worker_thread: Optional[threading.Thread] = None
_api_key: str = ""
_project_id: str = ""
_backend_url: str = "https://api.getsecurescout.com"
_running: bool = False

# Failure / Backoff tracking
_consecutive_failures: int = 0
_backoff_until: float = 0.0


def init_reporter(api_key: str, project_id: str, backend_url: str = "https://api.getsecurescout.com") -> None:
    """Initializes the background daemon worker and registers config attributes."""
    global _api_key, _project_id, _backend_url, _worker_thread, _running
    _api_key = api_key
    _project_id = project_id
    _backend_url = backend_url.rstrip("/")
    
    if not _running:
        _running = True
        _worker_thread = threading.Thread(target=_reporter_worker, daemon=True)
        _worker_thread.start()
        logger.info("SecureScout IAST background reporter initialized.")


def queue_finding(
    rule: str,
    tainted_value: str,
    source: str,
    field_name: str,
    request_id: str,
    query_snippet: str,
    stack_trace: List[str],
    endpoint: str
) -> None:
    """
    Callback function queued by database patches when a query matches a tainted string.
    Drops findings on queue overflow to preserve memory limits.
    """
    finding = {
        "rule": rule,
        "tainted_source": f"{source}:{field_name}" if field_name else source,
        "query_snippet": query_snippet,
        "endpoint": endpoint,
        "stack_trace": stack_trace,
        "request_id": request_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    try:
        # Non-blocking put to avoid hanging the customer request thread on overflow
        _finding_queue.put_nowait(finding)
    except queue.Full:
        logger.warning("SecureScout IAST telemetry queue is full. Dropping finding report.")


def send_heartbeat(framework: str = "fastapi") -> bool:
    """Transmits connection heartbeat payload to the backend."""
    url = f"{_backend_url}/v1/iast/heartbeat"
    payload = {
        "project_id": _project_id,
        "app_metadata": {
            "agent": "securescout-iast-python",
            "framework": framework,
            "python_version": sys.version.split()[0]
        }
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": _api_key,
            "User-Agent": "SecureScout-IAST-Agent/1.0"
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except Exception as e:
        logger.debug(f"Failed to transmit IAST heartbeat: {e}")
        return False


def _reporter_worker() -> None:
    """Daemon thread loop that reads from the queue and aggregates batches of findings."""
    global _running, _backoff_until
    while _running:
        # If backing off, sleep briefly and skip loop to avoid hammering the backend
        if time.time() < _backoff_until:
            time.sleep(5)
            continue

        batch = []
        try:
            # Block up to 5 seconds waiting for a queued finding
            item = _finding_queue.get(timeout=5)
            batch.append(item)
            
            # Drain up to 10 additional findings currently in the queue
            while len(batch) < 10:
                try:
                    batch.append(_finding_queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            pass

        if batch:
            _send_batch(batch)


def _send_batch(batch: List[dict]) -> bool:
    """Sends aggregated payload batch to the IAST findings endpoint. Implements backoff."""
    global _consecutive_failures, _backoff_until
    url = f"{_backend_url}/v1/iast/findings"
    payload = {
        "project_id": _project_id,
        "findings": batch
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": _api_key,
            "User-Agent": "SecureScout-IAST-Agent/1.0"
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 202:
                _consecutive_failures = 0
                return True
            else:
                logger.debug(f"SecureScout IAST findings ingestion rejected with status code: {response.status}")
    except Exception as e:
        logger.debug(f"Failed to transmit IAST findings payload: {e}")

    _consecutive_failures += 1
    if _consecutive_failures >= 3:
        _backoff_until = time.time() + 30  # Back off for 30 seconds
        logger.debug("SecureScout IAST reporter detected 3+ consecutive failures. Backing off for 30s.")
    return False
