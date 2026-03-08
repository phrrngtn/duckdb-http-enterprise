"""Integration tests that require Python for server-side verification.

These tests check behavior that can't be expressed in sqllogictest alone —
specifically, inspecting the Flask server's internal counters to verify
parallel execution. All pure SQL assertions live in test/sql/*.test.

Requires the Flask concurrency server running on localhost:8444.
Start it before running:  python test/flask_concurrency_server.py
"""

import json
import urllib.request

import duckdb
import pytest

EXTENSION_PATH = "build/release/http_client.duckdb_extension"
SERVER = "http://localhost:8444"


@pytest.fixture
def con():
    c = duckdb.connect(config={"allow_unsigned_extensions": "true"})
    c.execute(f"LOAD '{EXTENSION_PATH}'")
    return c


@pytest.fixture(autouse=True)
def reset_server():
    """Reset Flask server counters before each test."""
    try:
        urllib.request.urlopen(f"{SERVER}/reset")
    except Exception:
        pass
    yield


def test_parallel_execution(con):
    """Verify that requests within a chunk fire concurrently.

    This requires Python because we need to inspect the Flask server's
    /stats endpoint to check peak_concurrent_connections — something
    sqllogictest can't do.
    """
    con.execute(
        f"""SELECT r.response_status_code FROM (
            SELECT http_get('{SERVER}/slow/' || id::VARCHAR || '?delay=0.2') AS r
            FROM range(5) AS t(id))"""
    ).fetchall()
    stats = json.loads(urllib.request.urlopen(f"{SERVER}/stats").read())
    assert stats["total_requests"] == 5
    assert stats["peak_concurrent_connections"] > 1, (
        f"Expected parallel execution, got peak={stats['peak_concurrent_connections']}"
    )
