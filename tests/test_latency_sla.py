"""Latency SLA verification test."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time
from securescout_iast import reporter as rep

SLA_SECONDS = 10
RUNS = 5

received = threading.Event()
receive_time: list[float] = []


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(202)
        self.end_headers()
        receive_time.append(time.monotonic())
        received.set()

    def log_message(self, *args):
        pass  # silence console log spam during tests


def _start_mock_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _reset_reporter(mock_url):
    rep._api_key = "test-key"
    rep._project_id = "test-project"
    rep._backend_url = mock_url
    rep._consecutive_failures = 0
    rep._backoff_until = 0.0
    with rep._dedup_lock:
        rep._dedup_cache.clear()
    # Drain queue
    while not rep._finding_queue.empty():
        try:
            rep._finding_queue.get_nowait()
        except Exception:
            break


def test_finding_latency_sla():
    server, url = _start_mock_server()
    
    # Ensure reporter worker is running fresh for this test
    if rep._running:
        rep._running = False
        if rep._worker_thread:
            rep._worker_thread.join(timeout=2.0)
            rep._worker_thread = None

    rep.init_reporter(api_key="test-key", project_id="test-proj", backend_url=url)

    latencies = []

    for i in range(RUNS):
        received.clear()
        receive_time.clear()
        _reset_reporter(url)

        t0 = time.monotonic()
        rep.queue_finding(
            rule="sql_injection",
            tainted_value=f"payload-{i}-{time.time()}",
            source="query_param",
            field_name="q",
            request_id=f"req-{i}",
            query_snippet=f"SELECT * FROM users WHERE id = payload-{i}",
            stack_trace=[],
            endpoint=f"/test-endpoint-{i}",
        )

        fired = received.wait(timeout=SLA_SECONDS + 2)
        assert fired, f"Run {i+1}: finding never reached mock server within {SLA_SECONDS + 2}s"

        latency = receive_time[0] - t0
        latencies.append(latency)
        print(f"Run {i+1}: {latency:.3f}s")

    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95) - 1] if len(latencies) >= 20 else max(latencies)
    print(f"P95 latency: {p95:.3f}s (SLA: {SLA_SECONDS}s)")
    assert p95 < SLA_SECONDS, f"P95 latency {p95:.3f}s breached {SLA_SECONDS}s SLA"

    server.shutdown()
