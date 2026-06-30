import sqlite3
from fastapi import FastAPI
from securescout_iast import SecureScoutIastMiddleware, init

app = FastAPI()

# Wire in securescout_iast (using fake config parameters)
init(
    api_key="fake-key-for-smoke-test",
    project_id="fake-project-id",
    backend_url="http://127.0.0.1:8000"
)
app.add_middleware(SecureScoutIastMiddleware)

# Initialize in-memory DB and populate dummy data
conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
cursor.execute("INSERT INTO users (name) VALUES ('alice')")
cursor.execute("INSERT INTO users (name) VALUES ('bob')")
conn.commit()


@app.get("/vulnerable-search")
def vulnerable_search(name: str):
    # DANGEROUS: Concatenated raw query
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return {"results": rows}


@app.get("/safe-search")
def safe_search(name: str):
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    rows = cursor.fetchall()
    return {"results": rows}


from fastapi.responses import HTMLResponse

@app.get("/xss-vulnerable", response_class=HTMLResponse)
def xss_vulnerable(name: str):
    # Vulnerable: echoes query parameter unescaped in HTML response
    return f"<html><body>Hello {name}</body></html>"


@app.get("/xss-safe", response_class=HTMLResponse)
def xss_safe(name: str):
    # Safe: escapes input
    import html
    return f"<html><body>Hello {html.escape(name)}</body></html>"
