#!/usr/bin/env bash
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Install this launcher and a trusted verifier snapshot as described in
# doc/maintainer-guide.md. Keep verification independent of the working tree.
export LC_ALL=C
set -e
HOOK_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$HOOK_DIR/sv2-verify-commits/pre-push-hook.py" "$@"
