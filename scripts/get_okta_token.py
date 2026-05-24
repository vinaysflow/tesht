#!/usr/bin/env python3
"""
scripts/get_okta_token.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Obtain a real Okta id_token via the OAuth 2.0 Authorization Code flow with PKCE.

Prerequisites:
  - Free Okta developer account at https://developer.okta.com/signup
  - An "OIDC - Web Application" created in Okta admin console
  - Redirect URI configured to: http://localhost:8888/callback
  - Environment variables set (or a .env file loaded before running):
      OKTA_ISSUER         e.g. https://dev-1234567.okta.com/oauth2/default
      OKTA_CLIENT_ID      your Okta app's Client ID
      OKTA_CLIENT_SECRET  your Okta app's Client Secret  (optional if app is public)

Usage:
  # Interactive (opens browser):
  OKTA_ISSUER=https://dev-XXX.okta.com/oauth2/default \\
  OKTA_CLIENT_ID=your_client_id \\
  python scripts/get_okta_token.py

  # Pipe to demo:
  TOKEN=$(python scripts/get_okta_token.py --quiet)
  python scripts/demo_mega.py --okta-token "$TOKEN"

  # Save to file for reuse:
  python scripts/get_okta_token.py --save /tmp/pramana_okta_token.txt

Output:
  Prints the id_token to stdout (and optionally saves to a file).
  The token is also saved to /tmp/pramana_okta_token.txt by default.

PKCE flow used (RFC 7636) — no client secret required for SPA/native apps.
If OKTA_CLIENT_SECRET is set, Basic auth is used in the token exchange.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from pathlib import Path

try:
    import httpx
except ImportError:
    print("Error: httpx is required. Install with: pip install httpx", file=sys.stderr)
    sys.exit(1)

DEFAULT_TOKEN_PATH = "/tmp/pramana_okta_token.txt"
REDIRECT_URI = "http://localhost:8888/callback"
SCOPES = "openid profile email"


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256 method)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _is_auth0(issuer: str) -> bool:
    """Auth0 domains look like dev-xxx.us.auth0.com (no path component)."""
    return "auth0.com" in issuer


def _authorize_endpoint(issuer: str) -> str:
    if _is_auth0(issuer):
        return issuer.rstrip("/") + "/authorize"
    return issuer.rstrip("/") + "/v1/authorize"


def _token_endpoint(issuer: str) -> str:
    if _is_auth0(issuer):
        return issuer.rstrip("/") + "/oauth/token"
    return issuer.rstrip("/") + "/v1/token"


def _build_auth_url(
    issuer: str,
    client_id: str,
    state: str,
    code_challenge: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",  # Force re-login for demo clarity
    }
    return _authorize_endpoint(issuer) + "?" + urllib.parse.urlencode(params)


def _exchange_code_for_token(
    issuer: str,
    client_id: str,
    client_secret: str | None,
    code: str,
    code_verifier: str,
) -> dict:
    """Exchange authorization code for tokens."""
    token_endpoint = _token_endpoint(issuer)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth = None
    if client_secret:
        auth = (client_id, client_secret)

    resp = httpx.post(token_endpoint, data=payload, headers=headers, auth=auth, timeout=15.0)
    resp.raise_for_status()
    return resp.json()


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP server to capture the OAuth callback redirect."""

    auth_code: str | None = None
    received_state: str | None = None
    error: str | None = None

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            _CallbackHandler.auth_code = params["code"][0]
            _CallbackHandler.received_state = params.get("state", [None])[0]
            body = b"<html><body><h2>Authentication successful!</h2><p>You can close this window.</p></body></html>"
        elif "error" in params:
            _CallbackHandler.error = params.get("error_description", params.get("error", ["unknown"]))[0]
            body = f"<html><body><h2>Error</h2><p>{_CallbackHandler.error}</p></body></html>".encode()
        else:
            body = b"<html><body><p>Waiting...</p></body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress server logs


def get_okta_token(
    issuer: str,
    client_id: str,
    client_secret: str | None = None,
    quiet: bool = False,
) -> str:
    """
    Run the full Authorization Code + PKCE flow.
    Returns the id_token string.
    """
    state = secrets.token_urlsafe(16)
    code_verifier, code_challenge = _generate_pkce_pair()
    auth_url = _build_auth_url(issuer, client_id, state, code_challenge)

    if not quiet:
        print("Starting OAuth 2.0 Authorization Code + PKCE flow…", file=sys.stderr)
        print(f"Redirect URI: {REDIRECT_URI}", file=sys.stderr)
        print("Opening browser for Okta login…", file=sys.stderr)

    # Start callback server in a thread
    server = http.server.HTTPServer(("localhost", 8888), _CallbackHandler)
    server_thread = threading.Thread(target=server.handle_request)
    server_thread.daemon = True
    server_thread.start()

    webbrowser.open(auth_url)

    if not quiet:
        print(f"\nIf your browser did not open, visit:\n  {auth_url}\n", file=sys.stderr)

    # Wait for callback (up to 120 seconds)
    server_thread.join(timeout=120)

    if _CallbackHandler.error:
        print(f"Error: Okta returned an error: {_CallbackHandler.error}", file=sys.stderr)
        sys.exit(1)

    if not _CallbackHandler.auth_code:
        print("Error: No authorization code received within 120 seconds.", file=sys.stderr)
        sys.exit(1)

    if _CallbackHandler.received_state != state:
        print("Error: State mismatch — possible CSRF attack.", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        print("Authorization code received. Exchanging for tokens…", file=sys.stderr)

    tokens = _exchange_code_for_token(
        issuer, client_id, client_secret,
        _CallbackHandler.auth_code, code_verifier,
    )

    id_token = tokens.get("id_token")
    if not id_token:
        print(f"Error: No id_token in response: {list(tokens.keys())}", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        access_token = tokens.get("access_token", "")
        print(f"id_token obtained (length: {len(id_token)})", file=sys.stderr)
        if access_token:
            print(f"access_token obtained (length: {len(access_token)})", file=sys.stderr)

    return id_token


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Obtain a real Okta id_token via Authorization Code + PKCE"
    )
    parser.add_argument(
        "--issuer",
        default=os.environ.get("OKTA_ISSUER", ""),
        help="Okta issuer URL (e.g. https://dev-XXX.okta.com/oauth2/default)",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("OKTA_CLIENT_ID", ""),
        help="Okta application Client ID",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("OKTA_CLIENT_SECRET", ""),
        help="Okta application Client Secret (optional for PKCE apps)",
    )
    parser.add_argument(
        "--save",
        metavar="PATH",
        default=DEFAULT_TOKEN_PATH,
        help=f"Save the id_token to this file (default: {DEFAULT_TOKEN_PATH})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only output the raw id_token to stdout (no status messages)",
    )
    args = parser.parse_args()

    if not args.issuer:
        print(
            "Error: OKTA_ISSUER environment variable or --issuer argument is required.\n"
            "Get it from your Okta admin console: Security → API → Authorization Servers",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.client_id:
        print(
            "Error: OKTA_CLIENT_ID environment variable or --client-id argument is required.\n"
            "Get it from your Okta admin console: Applications → Your App → Client ID",
            file=sys.stderr,
        )
        sys.exit(1)

    client_secret = args.client_secret or None

    id_token = get_okta_token(
        issuer=args.issuer,
        client_id=args.client_id,
        client_secret=client_secret,
        quiet=args.quiet,
    )

    # Always save to file
    save_path = Path(args.save)
    save_path.write_text(id_token)
    if not args.quiet:
        print(f"\nid_token saved to: {save_path}", file=sys.stderr)
        print("\n─────────────────────────────────────────", file=sys.stderr)
        print("Use with demo_mega.py:", file=sys.stderr)
        print(f"  python scripts/demo_mega.py --okta-token {save_path}", file=sys.stderr)
        print("─────────────────────────────────────────\n", file=sys.stderr)

    # Print token to stdout
    print(id_token)


if __name__ == "__main__":
    main()
