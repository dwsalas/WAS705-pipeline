#!/usr/bin/env python3
"""
Test Case: Login Throttling / Brute-Force Protection
Sends repeated failed login attempts and checks whether the application
introduces a lockout, delay, or rate-limit response.

Reference: Lab 4 finding, CVE-2021-3663 regression
Expects: after N failed attempts, the app should respond with a 429,
a lockout message, or measurably increasing response delay.
"""

import os
import sys
import time
import requests
import urllib3
from urllib.parse import unquote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("FIREFLY_BASE_URL", "http://172.16.24.73")
ATTEMPTS = int(os.environ.get("LOGIN_ATTEMPTS", "18"))

LOGIN_URL = f"{BASE_URL}/login"


def get_csrf_token(session):
    resp = session.get(LOGIN_URL, verify=False)
    if resp.status_code == 429:
        return None, 429
    resp.raise_for_status()
    raw_token = session.cookies.get("XSRF-TOKEN")
    return (unquote(raw_token) if raw_token else None), resp.status_code


def attempt_login(session, attempt_num):
    csrf, csrf_status = get_csrf_token(session)
    if csrf_status == 429:
        return 429, 0.0

    headers = {}
    if csrf:
        headers["X-XSRF-TOKEN"] = csrf

    start = time.time()
    resp = session.post(
        LOGIN_URL,
        data={
            "email": "nonexistent_test_user@example.com",
            "password": "wrong-password-attempt",
        },
        headers=headers,
        allow_redirects=False,
        verify=False,
    )
    elapsed = time.time() - start
    return resp.status_code, elapsed


def main():
    print(f"Target: {LOGIN_URL}")
    print(f"Sending up to {ATTEMPTS} consecutive failed login attempts...\n")

    session = requests.Session()
    results = []

    for i in range(1, ATTEMPTS + 1):
        status, elapsed = attempt_login(session, i)
        results.append((i, status, elapsed))
        print(f"Attempt {i}: status={status} time={elapsed:.2f}s")

        if status == 429:
            print(f"\nRESULT: PASS — rate limiting triggered at attempt {i} (HTTP 429)")
            sys.exit(0)

    first_half_avg = sum(r[2] for r in results[:len(results)//2]) / (len(results)//2)
    second_half_avg = sum(r[2] for r in results[len(results)//2:]) / (len(results) - len(results)//2)

    print(f"\nAverage response time, first half: {first_half_avg:.2f}s")
    print(f"Average response time, second half: {second_half_avg:.2f}s")

    if second_half_avg > first_half_avg * 2:
        print("RESULT: PASS — response delay increased significantly, throttling likely present")
        sys.exit(0)

    print(f"\nRESULT: FAIL — no rate limiting or lockout observed after {ATTEMPTS} failed attempts")
    sys.exit(1)


if __name__ == "__main__":
    main()
