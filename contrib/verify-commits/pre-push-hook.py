#!/usr/bin/env python3
# Copyright (c) 2026 The sv2-tp developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Guard master pushes using a locally approved verifier snapshot."""

import pathlib
import subprocess
import sys


def reject(message):
    print(f"ERROR: master push rejected: {message}", file=sys.stderr)
    return 1


def main():
    # This script is installed alongside the trusted verifier and its data.
    verifier_dir = pathlib.Path(__file__).resolve().parent
    for line in sys.stdin:
        fields = line.split()
        if len(fields) != 4:
            return reject("malformed pre-push input")
        _local_ref, local_oid, remote_ref, remote_oid = fields
        if remote_ref != "refs/heads/master":
            continue
        if set(local_oid) == {"0"}:
            return reject("deleting master is not allowed")

        try:
            trusted_root = (verifier_dir / "trusted-git-root").read_text().strip()
            history = subprocess.check_output(
                ["git", "rev-list", "--first-parent", local_oid], text=True
            ).splitlines()
        except (OSError, subprocess.CalledProcessError) as error:
            return reject(f"cannot load the trusted history: {error}")
        if not trusted_root or trusted_root not in history:
            return reject("the trusted root must be on the first-parent history")
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
