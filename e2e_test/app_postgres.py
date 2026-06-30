import os
import psycopg2
from contextlib import asynccontextmanager
from fastapi import FastAPI
from securescout_iast import SecureScoutIastMiddleware, init

DATABASE_URL = os.getenv("IAST_TEST_DATABASE_URL", "")
DATABASE_URL_DDL = os.getenv("IAST_TEST_DATABASE_URL_DDL", "")

def get_connection():
    return psycopg2.connect(DATABASE_URL)

def get_connection_ddl():
    return psycopg2.connect(DATABASE_URL_DDL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup (DDL)
    if DATABASE_URL_DDL:
        conn = get_connection_ddl()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS iast_test_users (
                        id SERIAL PRIMARY KEY,
                        name TEXT
                    );
                """)
                cur.execute("SELECT COUNT(*) FROM iast_test_users;")
                count = cur.fetchone()[0]
                if count == 0:
                    cur.execute("INSERT INTO iast_test_users (name) VALUES ('Alice');")
                    cur.execute("INSERT INTO iast_test_users (name) VALUES ('Bob');")
                    conn.commit()
        finally:
            conn.close()
    yield
    # Shutdown (DDL)
    if DATABASE_URL_DDL:
        conn = get_connection_ddl()
        try:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS iast_test_users;")
                conn.commit()
        finally:
            conn.close()

app = FastAPI(lifespan=lifespan)

# Initialize securescout-iast agent
init(
    api_key="test-api-key",
    project_id="00000000-0000-0000-0000-000000000000"
)
app.add_middleware(SecureScoutIastMiddleware)

@app.get("/vulnerable-search")
def vulnerable_search(name: str):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # SQL Injection vulnerability: string concatenation
            query = f"SELECT * FROM iast_test_users WHERE name = '{name}'"
            cur.execute(query)
            results = cur.fetchall()
            return {"users": [{"id": r[0], "name": r[1]} for r in results]}
    finally:
        conn.close()

@app.get("/safe-search")
def safe_search(name: str):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Safe query: parameterized input
            query = "SELECT * FROM iast_test_users WHERE name = %s"
            cur.execute(query, (name,))
            results = cur.fetchall()
            return {"users": [{"id": r[0], "name": r[1]} for r in results]}
    finally:
        conn.close()
