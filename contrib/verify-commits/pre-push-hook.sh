#!/usr/bin/env bash
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
exec "$(dirname -- "$0")/pre-push-hook.py" "$@"
