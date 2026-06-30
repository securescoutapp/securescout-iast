# securescout-iast

Interactive Application Security Testing (IAST) runtime agent for Python web applications. Detects SQL injection vulnerabilities in real time by tracing untrusted request data as it flows into database queries during normal application traffic.

## How it works

`securescout-iast` tags incoming request data (query parameters, headers, cookies, and JSON/form body) at the ASGI layer, then watches for that data appearing in raw SQL execute calls. If untrusted input reaches a database query without being safely parameterized, a finding is reported to your SecureScout dashboard — confirmed by actual runtime execution, not static guesswork.

## Installation

```bash
pip install securescout-iast
```

## Quick start (FastAPI / Starlette)

```python
from fastapi import FastAPI
from securescout_iast import SecureScoutIastMiddleware, init

app = FastAPI()

init(
    api_key="ssk_live_your_api_key",
    project_id="your-project-id",
)
app.add_middleware(SecureScoutIastMiddleware)
```

Get your API key and project ID from **Settings → API Keys** and your project's **Runtime (IAST)** tab in the SecureScout dashboard.

## Supported database drivers

- `psycopg2` (sync PostgreSQL)
- `asyncpg` (async PostgreSQL, including async SQLAlchemy)

Drivers are detected automatically. If a driver isn't installed in your environment, that patch is silently skipped — no errors, no extra dependencies pulled in.

## Detected vulnerability classes

- SQL Injection (CWE-89) — v1

## Safety guarantees

- `init()` never raises. Misconfiguration or network issues degrade to a silent no-op, never a crash.
- Your request and database driver behavior are never modified — the agent only observes.
- Request bodies over 1MB are not buffered for taint analysis (still passed through to your app unmodified).
- No third-party dependencies. Pure standard library.

## Privacy

This agent inspects request data and SQL query text locally, within your application process, to detect taint matches. Only confirmed findings (rule type, query snippet, stack trace, endpoint) are sent to SecureScout — never raw request bodies or full traffic.

## License

MIT
