#!/usr/bin/env python3
# Copyright (c) 2026 The sv2-tp developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify master pushes."""

import pathlib
import subprocess
import sys


def reject(message):
    print(f"ERROR: master push rejected: {message}", file=sys.stderr)
    return 1


def main():
    verifier_dir = pathlib.Path("contrib/verify-commits")
    for line in sys.stdin:
        fields = line.split()
        if len(fields) != 4:
            continue
        _local_ref, local_oid, remote_ref, remote_oid = fields
        if remote_ref != "refs/heads/master":
            continue
        print(f"Verifying master candidate {local_oid}...", file=sys.stderr)
        try:
            result = subprocess.run(
                [sys.executable, str(verifier_dir / "verify-commits.py"), local_oid],
                check=False,
            )
        except OSError as error:
            return reject(f"cannot run the trusted verifier: {error}")
        if result.returncode != 0:
            return reject("commit signature, Tree-SHA512, or clean-merge verification failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
