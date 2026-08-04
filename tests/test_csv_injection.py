#!/usr/bin/env python3
"""
Test Case: CSV Formula Injection (INPV-21)
Checks whether transaction descriptions containing spreadsheet formula
payloads are properly escaped in exported CSV data.

Reference: Lab 3/4 INPV-21, GHSA-29w6-c52g-m8jc
Expects: league/csv EscapeFormula formatter prefixes dangerous leading
characters (=, +, -, @, tab, CR) with a single quote before export.
"""

import os
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("FIREFLY_BASE_URL", "http://172.16.24.73")
TOKEN = os.environ.get("FIREFLY_API_TOKEN")

if not TOKEN:
    print("ERROR: FIREFLY_API_TOKEN not set")
    sys.exit(2)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

PAYLOAD_DESCRIPTION = "=1+1+cmd|' /C calc'!A0 CSV_INJECTION_TEST"


def get_first_asset_account():
    resp = requests.get(f"{BASE_URL}/api/v1/accounts?type=asset", headers=HEADERS, verify=False)
    resp.raise_for_status()
    data = resp.json()["data"]
    if not data:
        print("ERROR: no asset accounts found, cannot create test transaction")
        sys.exit(2)
    return data[0]["id"]


def get_or_create_expense_account():
    resp = requests.get(f"{BASE_URL}/api/v1/accounts?type=expense", headers=HEADERS, verify=False)
    resp.raise_for_status()
    data = resp.json()["data"]
    if data:
        return data[0]["attributes"]["name"]
    return "CSV Injection Test Payee"


def create_test_transaction(asset_account_id, expense_account_name):
    body = {
        "error_if_duplicate_hash": False,
        "transactions": [
            {
                "type": "withdrawal",
                "date": "2026-08-01",
                "amount": "1.00",
                "description": PAYLOAD_DESCRIPTION,
                "source_id": asset_account_id,
                "destination_name": expense_account_name,
            }
        ],
    }
    resp = requests.post(f"{BASE_URL}/api/v1/transactions", headers=HEADERS, json=body, verify=False)
    if resp.status_code not in (200, 201):
        print(f"ERROR: failed to create test transaction: {resp.status_code} {resp.text}")
        sys.exit(2)
    return resp.json()["data"]["id"]


def export_transactions_csv():
    resp = requests.get(
        f"{BASE_URL}/api/v1/data/export/transactions",
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"},
        params={"start": "2026-01-01", "end": "2026-12-31"},
        verify=False,
    )
    resp.raise_for_status()
    return resp.text


def check_escaping(csv_content):
    for line in csv_content.splitlines():
        if "CSV_INJECTION_TEST" in line:
            print("Found payload line in export:")
            print(f"  {line}")
            if "\"'=1+1" in line or "\"'+1+1" in line:
                return True, line
            elif '"=1+1' in line:
                return False, line
    return None, None


def main():
    print(f"Target: {BASE_URL}")
    print("Setting up test transaction...")

    asset_id = get_first_asset_account()
    expense_name = get_or_create_expense_account()
    txn_id = create_test_transaction(asset_id, expense_name)
    print(f"Created test transaction id={txn_id}")

    print("Exporting transactions CSV...")
    csv_content = export_transactions_csv()

    escaped, line = check_escaping(csv_content)

    if escaped is None:
        print("RESULT: INCONCLUSIVE — payload not found in export")
        sys.exit(2)
    elif escaped:
        print("RESULT: PASS — formula payload was escaped correctly")
        sys.exit(0)
    else:
        print("RESULT: FAIL — formula payload was NOT escaped (INPV-21 present)")
        sys.exit(1)


if __name__ == "__main__":
    main()
