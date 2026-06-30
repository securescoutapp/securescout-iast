import pytest
from fastapi.testclient import TestClient
from securescout_iast.patches.sqlite3_patch import install_sqlite3_patch

# Findings storage list
findings = []

def custom_queue_finding(**kwargs):
    findings.append(kwargs)

# Install sqlite3 patch using our custom test hook
install_sqlite3_patch(custom_queue_finding)

# Import app *after* patching sqlite3 to guarantee cursor executes run intercepted logic
from e2e_test.app import app

client = TestClient(app)


def test_e2e_sqlite_injection():
    # Clear findings list
    findings.clear()

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
    assert "SELECT * FROM users WHERE name = 'hacker_value'" in finding["query_snippet"]
    assert len(finding["stack_trace"]) > 0

    # 2. Trigger safe search
    findings.clear()
    response = client.get("/safe-search?name=hacker_value")
    assert response.status_code == 200
    
    # Assert no finding was detected
    assert len(findings) == 0
