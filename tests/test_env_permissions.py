#!/usr/bin/env python3
"""
Test Case: Docker env-file Permissions and Secret Exposure
Checks whether the .env file on the deployment host has overly loose
permissions, and whether secrets are readable via `docker exec`.

Reference: Lab 4 findings §5.2 (.env permissions) and §5.4
(secrets visible via docker exec).

Expects: .env should be 600 or 640 (owner-only, or owner+group read).
Anything looser (e.g. 664, 644 with wide group/world access) is a finding.
Secrets should not be trivially dumpable via `docker exec ... env`.
"""

import os
import subprocess
import sys

TARGET_HOST = os.environ.get("FIREFLY_SSH_HOST", "172.16.24.73")
TARGET_USER = os.environ.get("FIREFLY_SSH_USER", "allan")
SSH_KEY = os.environ.get("FIREFLY_SSH_KEY", os.path.expanduser("~/.ssh/pipeline_key"))
ENV_PATH = os.environ.get("FIREFLY_ENV_PATH", "~/firefly-iii-cleanroom/.env")
CONTAINER_NAME = os.environ.get("FIREFLY_CONTAINER_NAME", "firefly_iii_core")

SAFE_PERMISSIONS = {"600", "640"}


def run_ssh(command):
    ssh_cmd = [
        "ssh",
        "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        f"{TARGET_USER}@{TARGET_HOST}",
        command,
    ]
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def check_env_permissions():
    print("--- .env file permissions ---")
    code, out, err = run_ssh(f"stat -c '%a' {ENV_PATH}")
    if code != 0:
        print(f"  ERROR: could not stat .env file: {err}")
        return None

    perms = out.strip()
    print(f"  Permissions: {perms}")

    if perms in SAFE_PERMISSIONS:
        print(f"  PASS — permissions ({perms}) restrict access appropriately")
        return True
    else:
        print(f"  FAIL — permissions ({perms}) are looser than expected (600/640)")
        return False


def check_docker_secret_exposure():
    print("\n--- docker exec secret exposure ---")
    code, out, err = run_ssh(f"docker exec {CONTAINER_NAME} env | grep -iE 'APP_KEY|DB_PASSWORD'")

    if code != 0 or not out:
        print("  PASS — no secret values returned via docker exec env dump")
        return True

    print("  Secrets found via docker exec:")
    for line in out.splitlines():
        key = line.split("=")[0]
        print(f"    {key}=<redacted, length {len(line.split('=', 1)[-1])}>")
    print("  FAIL — secrets are readable via docker exec")
    return False


def main():
    print(f"Target: {TARGET_USER}@{TARGET_HOST}")

    perm_result = check_env_permissions()
    secret_result = check_docker_secret_exposure()

    print("\n=== Summary ===")
    results = {".env permissions": perm_result, "docker exec secret exposure": secret_result}
    any_fail = any(r is False for r in results.values())
    any_inconclusive = any(r is None for r in results.values())

    for name, result in results.items():
        label = "PASS" if result is True else "FAIL" if result is False else "INCONCLUSIVE"
        print(f"{name}: {label}")

    if any_fail:
        print("\nOVERALL RESULT: FAIL — deployment hardening gap present")
        sys.exit(1)
    elif any_inconclusive:
        print("\nOVERALL RESULT: INCONCLUSIVE")
        sys.exit(2)
    else:
        print("\nOVERALL RESULT: PASS — no exposure found")
        sys.exit(0)


if __name__ == "__main__":
    main()
