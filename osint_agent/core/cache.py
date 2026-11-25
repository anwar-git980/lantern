"""SQLite response cache.

Cache keys are built from the method, URL and public query params only. Credentials live in
headers (or in a param this module refuses to look at), so nothing secret is hashed or stored.
"""

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

DB_PATH = Path(".cache/lantern.db")
# A provider that puts its key in the query string must not get it anywhere near the cache,
# not even hashed.
SECRET_PARAMS = frozenset({"api_key", "apikey", "key", "token", "access_token", "auth"})
# 404 is a real answer ("no such account"), so it is worth caching. 429 and 5xx are not answers.
CACHEABLE_STATUSES = (200, 404)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    key TEXT PRIMARY KEY,
    status INT NOT NULL,
    body TEXT NOT NULL,
    expires_at REAL NOT NULL
)
"""


def cache_key(method: str, url: str, params: dict | None = None) -> str:
    public = sorted(
        (name, str(value))
        for name, value in (params or {}).items()
        if name.lower() not in SECRET_PARAMS
    )
    payload = json.dumps([method.upper(), url, public], sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(_SCHEMA)
    conn.commit()
    return conn


def get(key: str) -> tuple[int, str] | None:
    """The cached (status, body), or None when absent or expired."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT status, body FROM responses WHERE key = ? AND expires_at > ?",
            (key, time.time()),
        ).fetchone()
    return (row[0], row[1]) if row else None


def put(key: str, status: int, body: str, ttl: float) -> None:
    if status not in CACHEABLE_STATUSES:
        return
    with closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO responses (key, status, body, expires_at) VALUES (?, ?, ?, ?)",
            (key, status, body, time.time() + ttl),
        )
