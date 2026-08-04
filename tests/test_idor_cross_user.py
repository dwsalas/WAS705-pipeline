#!/usr/bin/env python3
"""
Test Case: Cross-User API Token Authorization (IDOR)
Checks whether a second user's API token can read the first user's
accounts, transactions, and budgets, which would confirm missing
object-level authorization on the REST API.

Reference: Lab 4 flagged gap (API Token Misuse, PASTA Stage 6),
GHSA-5q8v-j673-m5v4. Previously untested due to single-user lab setup.
Targets specifically named in Lab 4: /api/v1/accounts, /api/v1/transactions,
/api/v1/budgets.

Expects: User 2's token should NOT be able to see User 1's data on any
of these endpoints. A 200 with User 1's real data means the
vulnerability is present for that resource type.
"""

import os
import sys
import requests

BASE_URL = os.environ.get("FIREFLY_BASE_URL", "http://172.16.24.73")
TOKEN_USER1 = os.environ.get("FIREFLY_API_TOKEN_USER1")
TOKEN_USER2 = os.environ.get("FIREFLY_API_TOKEN_USER2")

if not TOKEN_USER1 or not TOKEN_USER2:
    print("ERROR: both FIREFLY_API_TOKEN_USER1 and FIREFLY_API_TOKEN_USER2 must be set")
    sys.exit(2)


def get_headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def get_user1_resource(resource_type, list_endpoint, extra_params=None):
    params = extra_params or {}
    resp = requests.get(f"{BASE_URL}{list_endpoint}", headers=get_headers(TOKEN_USER1), params=params)
    resp.raise_for_status()
    data = resp.json()["data"]
    if not data:
        print(f"  SKIP: User 1 has no {resource_type} to test against")
        return None, None
    item = data[0]
    identifier = item["id"]
    label = (
        item["attributes"].get("name")
        or item["attributes"].get("description")
        or str(identifier)
    )
    return identifier, label


def attempt_cross_user_read(read_endpoint):
    return requests.get(f"{BASE_URL}{read_endpoint}", headers=get_headers(TOKEN_USER2))


def check_resource(resource_type, list_endpoint, read_endpoint_fmt, extra_params=None):
    print(f"\n--- {resource_type} ---")
    print(f"Fetching User 1's {resource_type} (using User 1's token)...")

    identifier, label = get_user1_resource(resource_type, list_endpoint, extra_params)
    if identifier is None:
        return None  # inconclusive/skip, not pass or fail

    print(f"User 1 {resource_type[:-1]} found: id={identifier} label={label!r}")

    read_endpoint = read_endpoint_fmt.format(id=identifier)
    print(f"Attempting to read via User 2's token: {read_endpoint}")
    resp = attempt_cross_user_read(read_endpoint)
    print(f"Status: {resp.status_code}")

    if resp.status_code == 200:
        body = resp.json()
        data = body.get("data")
        if isinstance(data, list):
            returned_label = data[0]["attributes"].get("name") or data[0]["attributes"].get("description") if data else None
        else:
            returned_label = (data or {}).get("attributes", {}).get("name") or (data or {}).get("attributes", {}).get("description")

        if returned_label == label:
            print(f"FAIL — User 2's token read User 1's {resource_type[:-1]} data")
            return False
        else:
            print(f"PASS — response did not contain User 1's actual data")
            return True
    elif resp.status_code in (403, 404):
        print(f"PASS — access correctly denied (status {resp.status_code})")
        return True
    else:
        print(f"INCONCLUSIVE — unexpected status {resp.status_code}")
        return None


def main():
    print(f"Target: {BASE_URL}")

    results = {}
    results["accounts"] = check_resource(
        "accounts",
        "/api/v1/accounts?type=asset",
        "/api/v1/accounts/{id}",
    )
    results["transactions"] = check_resource(
        "transactions",
        "/api/v1/transactions",
        "/api/v1/transactions/{id}",
    )
    results["budgets"] = check_resource(
        "budgets",
        "/api/v1/budgets",
        "/api/v1/budgets/{id}",
    )

    print("\n=== Summary ===")
    any_fail = False
    any_inconclusive = False
    for resource, result in results.items():
        if result is True:
            print(f"{resource}: PASS")
        elif result is False:
            print(f"{resource}: FAIL")
            any_fail = True
        else:
            print(f"{resource}: INCONCLUSIVE / SKIPPED")
            any_inconclusive = True

    if any_fail:
        print("\nOVERALL RESULT: FAIL — cross-user data exposure found (IDOR present)")
        sys.exit(1)
    elif any_inconclusive:
        print("\nOVERALL RESULT: INCONCLUSIVE — some resources could not be tested")
        sys.exit(2)
    else:
        print("\nOVERALL RESULT: PASS — no cross-user data exposure found")
        sys.exit(0)


if __name__ == "__main__":
    main()
