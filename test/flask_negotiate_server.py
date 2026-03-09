#!/usr/bin/env python3
"""
Minimal Flask HTTPS server for testing Negotiate (SPNEGO/Kerberos) authentication.

Usage:
    # Generate self-signed cert (one-time):
    openssl req -x509 -newkey rsa:2048 -keyout test/key.pem -out test/cert.pem \
        -days 365 -nodes -subj '/CN=localhost'

    # Run the server:
    python3 test/flask_negotiate_server.py

    # Test with curl:
    curl -k --negotiate -u : https://localhost:8443/data.csv

    # Test with DuckDB:
    duckdb -unsigned -cmd "LOAD 'build/release/http_enterprise.duckdb_extension';" -c "
        SELECT * FROM http_get('https://localhost:8443/data.json',
            headers := MAP {'Authorization': negotiate_auth_header('https://localhost:8443/data.json')});
    "

For full Kerberos validation, set KRB5_KTNAME to point to a keytab containing
the HTTP/localhost principal and install the 'gssapi' Python package. Without
these, the server accepts any Negotiate token (useful for testing the token
generation path without a full KDC setup).
"""

import base64
import json
import os
import ssl
import sys

from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Try to import gssapi for real token validation
try:
    import gssapi
    HAS_GSSAPI = True
except ImportError:
    HAS_GSSAPI = False
    print("WARNING: gssapi module not available. Negotiate tokens will be accepted without validation.",
          file=sys.stderr)


def validate_negotiate_token(token_b64):
    """Validate a SPNEGO token. Returns (success, principal_name)."""
    if not HAS_GSSAPI:
        # Without gssapi, we can still decode and inspect the token
        try:
            token_bytes = base64.b64decode(token_b64)
            # A valid SPNEGO token starts with ASN.1 APPLICATION [0] tag (0x60)
            if len(token_bytes) > 0 and token_bytes[0] == 0x60:
                return True, "unvalidated (no gssapi)"
            else:
                return False, "invalid token format"
        except Exception as e:
            return False, str(e)

    # Real validation with gssapi
    try:
        server_creds = gssapi.Credentials(usage='accept')
        sec_context = gssapi.SecurityContext(creds=server_creds, usage='accept')
        token_bytes = base64.b64decode(token_b64)
        sec_context.step(token_bytes)
        principal = str(sec_context.initiator_name)
        return True, principal
    except Exception as e:
        return False, str(e)


def require_negotiate(f):
    """Decorator that enforces Negotiate authentication."""
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Negotiate '):
            resp = Response(
                json.dumps({"error": "Negotiate authentication required"}),
                status=401,
                mimetype='application/json'
            )
            resp.headers['WWW-Authenticate'] = 'Negotiate'
            return resp

        token_b64 = auth_header[len('Negotiate '):]
        success, principal = validate_negotiate_token(token_b64)

        if not success:
            resp = Response(
                json.dumps({"error": f"Token validation failed: {principal}"}),
                status=401,
                mimetype='application/json'
            )
            resp.headers['WWW-Authenticate'] = 'Negotiate'
            return resp

        print(f"Authenticated: {principal}", file=sys.stderr)
        # Pass the principal to the handler via request context
        request.authenticated_principal = principal
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


@app.route('/data.csv')
@require_negotiate
def data_csv():
    csv_data = "id,name,value\n1,alpha,100\n2,beta,200\n3,gamma,300\n"
    return Response(csv_data, mimetype='text/csv')


@app.route('/data.json')
@require_negotiate
def data_json():
    data = {
        "items": [
            {"id": 1, "name": "alpha", "value": 100},
            {"id": 2, "name": "beta", "value": 200},
            {"id": 3, "name": "gamma", "value": 300},
        ],
        "authenticated_as": request.authenticated_principal,
    }
    return jsonify(data)


@app.route('/health')
def health():
    """Unauthenticated health check endpoint."""
    return jsonify({
        "status": "ok",
        "gssapi_available": HAS_GSSAPI,
        "keytab": os.environ.get('KRB5_KTNAME', 'not set'),
    })


if __name__ == '__main__':
    cert_file = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_file = os.path.join(os.path.dirname(__file__), 'key.pem')

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Generating self-signed certificate...", file=sys.stderr)
        os.system(
            f"openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} "
            f"-days 365 -nodes -subj '/CN=localhost' 2>/dev/null"
        )

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cert_file, key_file)

    print("Starting Negotiate test server on https://localhost:8443", file=sys.stderr)
    print(f"  gssapi available: {HAS_GSSAPI}", file=sys.stderr)
    print(f"  KRB5_KTNAME: {os.environ.get('KRB5_KTNAME', 'not set')}", file=sys.stderr)
    print("", file=sys.stderr)
    print("Endpoints:", file=sys.stderr)
    print("  GET /health     - unauthenticated health check", file=sys.stderr)
    print("  GET /data.csv   - requires Negotiate auth, returns CSV", file=sys.stderr)
    print("  GET /data.json  - requires Negotiate auth, returns JSON", file=sys.stderr)

    app.run(host='localhost', port=8443, ssl_context=ssl_ctx)
