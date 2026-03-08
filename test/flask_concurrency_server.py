#!/usr/bin/env python3
"""
Flask server for testing concurrency behavior of duckdb-http-client.

Tracks concurrent connections, logs arrival/departure times, and simulates
slow responses. Use this to observe whether DuckDB parallelizes HTTP requests
from scalar/table functions.

Usage:
    python3 test/flask_concurrency_server.py

    # Then from DuckDB:
    duckdb -unsigned -cmd "LOAD 'build/release/http_client.duckdb_extension';" -c "
        SELECT id, json_extract(http_request('GET',
            'http://localhost:8444/slow/' || id::VARCHAR,
            NULL, NULL, NULL), '$.response_status_code')::INTEGER AS status
        FROM range(10) AS t(id);
    "

    # Check what the server saw:
    curl http://localhost:8444/stats
"""

import json
import os
import sys
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request, Response

app = Flask(__name__)

# --- Concurrency tracking ---

lock = threading.Lock()
active_connections = 0
peak_connections = 0
total_requests = 0
request_log = []  # list of {id, thread, arrived, departed, duration, concurrent_on_arrival}


@app.route('/slow/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def slow_endpoint(path):
    """Respond after a configurable delay. Default 0.5s, override with ?delay=N."""
    global active_connections, peak_connections, total_requests

    delay = float(request.args.get('delay', 0.5))
    arrived = time.time()

    with lock:
        active_connections += 1
        total_requests += 1
        req_id = total_requests
        concurrent = active_connections
        if active_connections > peak_connections:
            peak_connections = active_connections

    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] "
          f"REQ #{req_id:3d} arrived  | concurrent={concurrent:2d} | "
          f"thread={threading.current_thread().name} | path=/{path}",
          file=sys.stderr)

    time.sleep(delay)

    with lock:
        active_connections -= 1

    departed = time.time()
    duration = departed - arrived

    with lock:
        request_log.append({
            'id': req_id,
            'path': path,
            'thread': threading.current_thread().name,
            'arrived': round(arrived, 3),
            'departed': round(departed, 3),
            'duration': round(duration, 3),
            'concurrent_on_arrival': concurrent,
        })

    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] "
          f"REQ #{req_id:3d} departed | duration={duration:.3f}s | "
          f"active_now={active_connections}",
          file=sys.stderr)

    return jsonify({
        'request_id': req_id,
        'path': path,
        'delay': delay,
        'duration': round(duration, 3),
        'concurrent_on_arrival': concurrent,
        'thread': threading.current_thread().name,
    })


@app.route('/fast', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def fast_endpoint():
    """Respond immediately. For measuring raw throughput."""
    global active_connections, peak_connections, total_requests

    with lock:
        active_connections += 1
        total_requests += 1
        req_id = total_requests
        concurrent = active_connections
        if active_connections > peak_connections:
            peak_connections = active_connections

    with lock:
        active_connections -= 1

    return jsonify({'request_id': req_id, 'concurrent': concurrent})


@app.route('/stats')
def stats():
    """Return concurrency statistics and the full request log."""
    with lock:
        return jsonify({
            'total_requests': total_requests,
            'peak_concurrent_connections': peak_connections,
            'active_connections': active_connections,
            'request_log': request_log,
        })


@app.route('/reset')
def reset():
    """Reset all counters and logs."""
    global active_connections, peak_connections, total_requests, request_log
    with lock:
        active_connections = 0
        peak_connections = 0
        total_requests = 0
        request_log = []
    return jsonify({'status': 'reset'})


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'threads': threading.active_count()})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8444))
    # threaded=True is Flask's default in dev mode — each request gets its own thread.
    # This lets us observe whether DuckDB sends requests concurrently.
    print(f"Starting concurrency test server on http://localhost:{port}", file=sys.stderr)
    print(f"  GET /slow/<path>?delay=0.5  — delayed response (tracks concurrency)", file=sys.stderr)
    print(f"  GET /fast                   — instant response", file=sys.stderr)
    print(f"  GET /stats                  — concurrency statistics", file=sys.stderr)
    print(f"  GET /reset                  — reset counters", file=sys.stderr)
    app.run(host='localhost', port=port, threaded=True)
