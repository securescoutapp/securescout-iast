import os
import pytest
from fastapi.testclient import TestClient

# Skip all tests in this file if IAST_TEST_DATABASE_URL or IAST_TEST_DATABASE_URL_DDL is not set
DATABASE_URL = os.getenv("IAST_TEST_DATABASE_URL")
DATABASE_URL_DDL = os.getenv("IAST_TEST_DATABASE_URL_DDL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL or not DATABASE_URL_DDL,
    reason="IAST_TEST_DATABASE_URL or IAST_TEST_DATABASE_URL_DDL env var not set"
)

# Set the environment variables so app_postgres sees them before importing
os.environ["IAST_TEST_DATABASE_URL"] = DATABASE_URL or ""
os.environ["IAST_TEST_DATABASE_URL_DDL"] = DATABASE_URL_DDL or ""

# Patch psycopg2 after importing the app to override production init callback
findings = []

def custom_queue_finding(**kwargs):
    findings.append(kwargs)

from e2e_test.app_postgres import app
from securescout_iast.patches.psycopg2_patch import install_psycopg2_patch
install_psycopg2_patch(custom_queue_finding)

@pytest.fixture(autouse=True)
def setup_teardown():
    # Clear findings list before test
    findings.clear()
    yield
    # Explicit final cleanup of table to ensure no artifacts remain
    import psycopg2
    try:
        conn = psycopg2.connect(DATABASE_URL_DDL)
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS iast_test_users;")
            conn.commit()
        conn.close()
    except Exception:
        pass

def test_e2e_postgres_injection():
    with TestClient(app) as client:
        # 1. Trigger vulnerable search (hacker_value is >= 6 chars)
        response = client.get("/vulnerable-search?name=hacker_value")
        assert response.status_code == 200

        # Assert finding was detected and attributes match context
        assert len(findings) == 1
        finding = findings[0]
        assert finding["rule"] == "sql_injection"
        assert finding["tainted_value"] == "hacker_value"
        assert finding["source"] == "query_param"
        assert finding["field_name"] == "name"
        assert finding["endpoint"] == "GET /vulnerable-search"
        assert len(finding["stack_trace"]) > 0

        # Clear findings
        findings.clear()

        # 2. Trigger safe search
        response = client.get("/safe-search?name=hacker_value")
        assert response.status_code == 200
        assert len(findings) == 0
