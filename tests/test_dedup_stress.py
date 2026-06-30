"""Stress test to measure telemetry queue churn and deduplication logic."""
import queue
import threading
from securescout_iast import reporter


def test_unbounded_churn():
    # Clear dedup cache and reset queue
    reporter._dedup_cache.clear()
    reporter._finding_queue = queue.Queue(maxsize=500)
    initial_queue_size = reporter._finding_queue.qsize()
    assert initial_queue_size == 0

    # Call queue_finding 1000 times with identical fingerprint
    for i in range(1000):
        reporter.queue_finding(
            rule="sql_injection",
            tainted_value="hacker_value",
            source="query_param",
            field_name="q",
            request_id=f"req-{i}",
            query_snippet="SELECT * FROM users",
            stack_trace=["line 1", "line 2"],
            endpoint="GET /search",
        )

    final_queue_size = reporter._finding_queue.qsize()
    print(f"\n[STRESS TEST AFTER] Enqueued: {final_queue_size}")
    print(f"[STRESS TEST AFTER] Suppressed: {1000 - final_queue_size}")

    # Assert only 1 finding is enqueued (the first one) and all duplicates are suppressed
    assert final_queue_size == 1

    # Call with a unique endpoint (should pass through)
    reporter.queue_finding(
        rule="sql_injection",
        tainted_value="hacker_value",
        source="query_param",
        field_name="q",
        request_id="req-unique-1",
        query_snippet="SELECT * FROM users",
        stack_trace=["line 1", "line 2"],
        endpoint="GET /another-endpoint",
    )
    assert reporter._finding_queue.qsize() == 2

    # Call with a unique tainted value (should pass through)
    reporter.queue_finding(
        rule="sql_injection",
        tainted_value="another_hacker_value",
        source="query_param",
        field_name="q",
        request_id="req-unique-2",
        query_snippet="SELECT * FROM users",
        stack_trace=["line 1", "line 2"],
        endpoint="GET /search",
    )
    assert reporter._finding_queue.qsize() == 3


def test_concurrent_churn():
    # Clear dedup cache and reset queue
    reporter._dedup_cache.clear()
    reporter._finding_queue = queue.Queue(maxsize=500)

    # Spin up 50 threads calling queue_finding 20 times each
    threads = []

    def worker():
        for i in range(20):
            reporter.queue_finding(
                rule="sql_injection",
                tainted_value="hacker_value",
                source="query_param",
                field_name="q",
                request_id=f"req-thread-{i}",
                query_snippet="SELECT * FROM users",
                stack_trace=["line 1", "line 2"],
                endpoint="GET /search",
            )

    for _ in range(50):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    final_queue_size = reporter._finding_queue.qsize()
    print(f"[CONCURRENT TEST AFTER] Queue size: {final_queue_size}")
    
    # Assert only 1 finding is enqueued across all concurrent threads
    assert final_queue_size == 1
