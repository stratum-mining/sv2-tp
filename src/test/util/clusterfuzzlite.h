// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_CLUSTERFUZZLITE_H
#define BITCOIN_TEST_UTIL_CLUSTERFUZZLITE_H

// Detect whether the current process is running under ClusterFuzzLite.
// Some workflows strip custom environment variables during replay, so the
// implementation falls back to bundle metadata when needed.
bool RunningUnderClusterFuzzLite();

// Ensure MSan builds running under ClusterFuzzLite point at the bundled
// llvm-symbolizer, re-execing once if needed so the runtime observes the
// updated environment. No-op on non-MSan builds.
void EnsureClusterFuzzLiteMsanSymbolizer(int argc, char** argv);

#endif // BITCOIN_TEST_UTIL_CLUSTERFUZZLITE_H
