// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/clusterfuzzlite.h>

#include <util/fs.h>

#include <array>
#include <cstdlib>

#if defined(__linux__)
#include <unistd.h>
#endif

namespace {

#if defined(__linux__)
static bool BundleMarkerPresent()
{
    constexpr std::size_t PROC_SELF_EXE_BUF_SZ{4096};
    std::array<char, PROC_SELF_EXE_BUF_SZ> proc_exe{};
    const ssize_t read_bytes{::readlink("/proc/self/exe", proc_exe.data(), proc_exe.size() - 1)};
    if (read_bytes <= 0 || static_cast<std::size_t>(read_bytes) >= proc_exe.size()) {
        return false;
    }

    proc_exe[static_cast<std::size_t>(read_bytes)] = '\0';
    const fs::path exe_path{proc_exe.data()};

    const fs::path marker{exe_path.parent_path() / ".sv2-clusterfuzzlite"};
    return fs::exists(marker);
}
#endif // defined(__linux__)

} // namespace

bool RunningUnderClusterFuzzLite()
{
    static const bool kRunningUnderCfl = [] {
        const char* const cifuzz{std::getenv("CIFUZZ")};
        if (cifuzz != nullptr && cifuzz[0] != '\0') {
            return true;
        }
#if defined(__linux__)
        if (BundleMarkerPresent()) {
            return true;
        }
#endif
        return false;
    }();
    return kRunningUnderCfl;
}
