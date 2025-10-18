// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/clusterfuzzlite.h>

#include <util/fs.h>
#include <util/sanitizer.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#if defined(__linux__)
#include <unistd.h>
#endif

using util::sanitizer::GetEnvUnpoisoned;
using util::sanitizer::Unpoison;
using util::sanitizer::UnpoisonArray;
using util::sanitizer::UnpoisonCString;
using util::sanitizer::UnpoisonMemory;
using util::sanitizer::UnpoisonPath;

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define CLUSTERFUZZLITE_HAVE_MSAN 1
#endif
#endif

#ifdef CLUSTERFUZZLITE_HAVE_MSAN
#include <sanitizer/msan_interface.h>
#if defined(__has_include)
#if __has_include(<sanitizer/sanitizer_flags.h>)
#define CLUSTERFUZZLITE_HAVE_SANITIZER_COMMON_FLAGS 1
#include <sanitizer/sanitizer_flags.h>
#endif
#endif
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
    UnpoisonArray(proc_exe.data(), proc_exe.size());
    fs::path exe_path{proc_exe.data()};
    UnpoisonPath(exe_path);

    fs::path marker{exe_path.parent_path() / ".sv2-clusterfuzzlite"};
    UnpoisonPath(marker);
    return fs::exists(marker);
}
#endif // defined(__linux__)

} // namespace

bool RunningUnderClusterFuzzLite()
{
    static const bool kRunningUnderCfl = [] {
        const char* const cifuzz{GetEnvUnpoisoned("CIFUZZ")};
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

#ifdef CLUSTERFUZZLITE_HAVE_MSAN

namespace {

static bool MsanSymbolizerDebuggingEnabled()
{
    static const bool kDebug = [] {
        const char* const debug_env{GetEnvUnpoisoned("SV2_DEBUG_MSAN_SYMBOLIZER")};
        return debug_env != nullptr && debug_env[0] != '\0';
    }();
    return kDebug;
}

static void LogMsanSymbolizerState(const char* context)
{
    if (!RunningUnderClusterFuzzLite() || !MsanSymbolizerDebuggingEnabled()) return;

    const char* const llvm_symbolizer{GetEnvUnpoisoned("LLVM_SYMBOLIZER_PATH")};
    const char* const msan_options{GetEnvUnpoisoned("MSAN_OPTIONS")};
    std::fprintf(stderr, "[cfl] %s: LLVM_SYMBOLIZER_PATH='%s'\n", context, (llvm_symbolizer != nullptr && llvm_symbolizer[0] != '\0') ? llvm_symbolizer : "<unset>");
    std::fprintf(stderr, "[cfl] %s: MSAN_OPTIONS='%s'\n", context, (msan_options != nullptr && msan_options[0] != '\0') ? msan_options : "<unset>");
#if defined(CLUSTERFUZZLITE_HAVE_SANITIZER_COMMON_FLAGS)
    const auto* const flags{__sanitizer::common_flags()};
    const char* const cached{(flags != nullptr) ? flags->external_symbolizer_path : nullptr};
    std::fprintf(stderr, "[cfl] %s: cached external_symbolizer_path='%s'\n", context, (cached != nullptr && cached[0] != '\0') ? cached : "<empty>");
#else
    std::fprintf(stderr, "[cfl] %s: cached external_symbolizer_path='<unavailable>'\n", context);
#endif
}

static void MaybeReexecForMsanSymbolizer(int argc, char** argv)
{
#if defined(__linux__)
    if (!RunningUnderClusterFuzzLite()) return;
    if (argv == nullptr || argc <= 0 || argv[0] == nullptr) return;

    const char* const disable_reexec{GetEnvUnpoisoned("SV2_DISABLE_MSAN_SYMBOLIZER_REEXEC")};
    if (disable_reexec != nullptr && disable_reexec[0] != '\0') return;

    const char* const msan_options{GetEnvUnpoisoned("MSAN_OPTIONS")};
    if (msan_options == nullptr || std::strstr(msan_options, "external_symbolizer_path=") == nullptr) return;

    const char* const already_reexecuted{GetEnvUnpoisoned("SV2_MSAN_SYMBOLIZER_REEXECUTED")};
    if (already_reexecuted != nullptr && already_reexecuted[0] != '\0') return;

    setenv("SV2_MSAN_SYMBOLIZER_REEXECUTED", "1", 1);
    LogMsanSymbolizerState("pre-reexec");
    if (RunningUnderClusterFuzzLite()) {
        std::fprintf(stderr, "[cfl] re-exec requested; attempting execve('%s')\n", argv[0]);
    }

    extern char** environ;
    if (execve(argv[0], argv, environ) != 0) {
        if (RunningUnderClusterFuzzLite()) {
            std::fprintf(stderr, "[cfl] execve failed: %s\n", std::strerror(errno));
        }
        unsetenv("SV2_MSAN_SYMBOLIZER_REEXECUTED");
    }
#else
    (void)argc;
    (void)argv;
#endif
}

static void EnsureMsanExternalSymbolizer(const std::string& symbolizer_path)
{
    const char* existing{GetEnvUnpoisoned("MSAN_OPTIONS")};

    std::string new_opts{"external_symbolizer_path="};
    new_opts.append(symbolizer_path);
    if (existing != nullptr && existing[0] != '\0') {
        const char* cursor{existing};
        bool appended_extra{false};
        while (true) {
            const char* const sep{std::strchr(cursor, ':')};
            std::string token;
            if (sep != nullptr) {
                token.assign(cursor, static_cast<std::size_t>(sep - cursor));
            } else {
                token.assign(cursor);
            }
            if (!token.empty() && !token.starts_with("external_symbolizer_path=")) {
                if (!appended_extra) {
                    new_opts.push_back(':');
                    appended_extra = true;
                } else {
                    new_opts.push_back(':');
                }
                new_opts.append(token);
            }
            if (sep == nullptr) {
                break;
            }
            cursor = sep + 1;
        }
    }
    setenv("MSAN_OPTIONS", new_opts.c_str(), 1);

    if (RunningUnderClusterFuzzLite() && MsanSymbolizerDebuggingEnabled()) {
        std::fprintf(stderr, "[cfl] MSAN_OPTIONS now '%s'\n", new_opts.c_str());
    }
    LogMsanSymbolizerState("EnsureMsanExternalSymbolizer");
}

static void ExportSymbolizerEnvFromUtf8(const std::string& sym)
{
    setenv("LLVM_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("ASAN_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("MSAN_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("UBSAN_SYMBOLIZER_PATH", sym.c_str(), 1);

    EnsureMsanExternalSymbolizer(sym);
}

#if defined(_WIN32)
static void ExportSymbolizerEnv(const fs::path& symbolizer_path)
{
    ExportSymbolizerEnvFromUtf8(fs::PathToString(symbolizer_path));
}
#endif

#if !defined(_WIN32)
static bool TryExportSymbolizerFromUtf8(std::string& symbolizer_utf8)
{
    if (symbolizer_utf8.empty()) return false;
    UnpoisonMemory(symbolizer_utf8.c_str(), symbolizer_utf8.size() + 1);
    if (::access(symbolizer_utf8.c_str(), X_OK) != 0) {
        if (RunningUnderClusterFuzzLite()) {
            std::fprintf(stderr, "[cfl] llvm-symbolizer candidate '%s' not usable: %s\n", symbolizer_utf8.c_str(), std::strerror(errno));
        }
        return false;
    }

    ExportSymbolizerEnvFromUtf8(symbolizer_utf8);
    if (RunningUnderClusterFuzzLite()) {
        std::fprintf(stderr, "[cfl] configured llvm-symbolizer at '%s'\n", symbolizer_utf8.c_str());
    }
    return true;
}
#else
static bool TryExportSymbolizerFromUtf8(std::string& symbolizer_utf8)
{
    if (symbolizer_utf8.empty()) return false;
    fs::path symbolizer_path{fs::PathFromString(symbolizer_utf8)};
    UnpoisonPath(symbolizer_path);
    if (!fs::exists(symbolizer_path) || !fs::is_regular_file(symbolizer_path)) return false;

    ExportSymbolizerEnv(symbolizer_path);
    return true;
}
#endif

static bool TryExportSymbolizerFromEnv(const char* configured_symbolizer)
{
    if (configured_symbolizer == nullptr || configured_symbolizer[0] == '\0') return false;
    const std::size_t configured_len{std::strlen(configured_symbolizer)};
    if (configured_len == 0) return false;
    UnpoisonMemory(configured_symbolizer, configured_len + 1);

    std::string configured{configured_symbolizer};
    return TryExportSymbolizerFromUtf8(configured);
}

static void ConfigureClusterFuzzLiteMsanSymbolizer(int argc, char** argv)
{
    const char* const configured_symbolizer{GetEnvUnpoisoned("LLVM_SYMBOLIZER_PATH")};
    if (TryExportSymbolizerFromEnv(configured_symbolizer)) {
        LogMsanSymbolizerState("MaybeConfigureSymbolizer(from-env)");
        MaybeReexecForMsanSymbolizer(argc, argv);
        return;
    }

    const char* log_context{"MaybeConfigureSymbolizer(no-change)"};

    try {
        fs::path exe_path;
        bool have_exe_path{false};

#if defined(__linux__)
        {
            constexpr std::size_t PROC_SELF_EXE_BUF_SZ{4096};
            std::array<char, PROC_SELF_EXE_BUF_SZ> proc_exe{};
            const ssize_t read_bytes{::readlink("/proc/self/exe", proc_exe.data(), proc_exe.size() - 1)};
            if (read_bytes > 0 && static_cast<std::size_t>(read_bytes) < proc_exe.size()) {
                proc_exe[static_cast<std::size_t>(read_bytes)] = '\0';
                UnpoisonArray(proc_exe.data(), proc_exe.size());
                fs::path discovered{proc_exe.data()};
                UnpoisonPath(discovered);
                exe_path = std::move(discovered);
                UnpoisonPath(exe_path);
                have_exe_path = exe_path.is_absolute();
            }
        }
#endif

        if (!have_exe_path) {
            const char* const argv0{(argv != nullptr && argc > 0) ? argv[0] : nullptr};
            if (argv0 == nullptr) {
                if (RunningUnderClusterFuzzLite()) {
                    std::fprintf(stderr, "[cfl] Unable to discover executable path (argv0 missing).\n");
                }
                LogMsanSymbolizerState("MaybeConfigureSymbolizer(no-argv0)");
                MaybeReexecForMsanSymbolizer(argc, argv);
                return;
            }
            Unpoison(argv0);
            UnpoisonCString(argv0);
            fs::path candidate{argv0};
            UnpoisonPath(candidate);
            if (candidate.empty()) return;
            if (!candidate.is_absolute()) {
                fs::path resolved{fs::current_path()};
                UnpoisonPath(resolved);
                resolved /= candidate;
                UnpoisonPath(resolved);
                exe_path = std::move(resolved);
            } else {
                exe_path = std::move(candidate);
            }
            UnpoisonPath(exe_path);
            have_exe_path = exe_path.is_absolute();
        }

        const std::string exe_string{fs::PathToString(exe_path)};
        if (exe_string.empty()) return;

        std::string symbolizer_string;
        const auto last_slash{exe_string.find_last_of('/')};
        const auto last_sep{exe_string.find_last_of(fs::path::preferred_separator)};
        const auto sep_index{std::max(last_slash, last_sep)};
        if (sep_index != std::string::npos) {
            symbolizer_string.assign(exe_string.data(), sep_index + 1);
        } else {
            symbolizer_string.assign("./");
        }
        symbolizer_string.append("llvm-symbolizer");

        if (!TryExportSymbolizerFromUtf8(symbolizer_string)) {
            if (RunningUnderClusterFuzzLite()) {
                std::fprintf(stderr, "[cfl] Failed to configure llvm-symbolizer relative to '%s'.\n", exe_string.c_str());
            }
            LogMsanSymbolizerState("MaybeConfigureSymbolizer(relative-failure)");
            MaybeReexecForMsanSymbolizer(argc, argv);
            return;
        }
        log_context = "MaybeConfigureSymbolizer(relative-success)";
    } catch (const fs::filesystem_error&) {
        log_context = "MaybeConfigureSymbolizer(fs-exception)";
    }

    LogMsanSymbolizerState(log_context);
    MaybeReexecForMsanSymbolizer(argc, argv);
}

} // namespace

void EnsureClusterFuzzLiteMsanSymbolizer(int argc, char** argv)
{
    ConfigureClusterFuzzLiteMsanSymbolizer(argc, argv);
}

#else

void EnsureClusterFuzzLiteMsanSymbolizer(int argc, char** argv)
{
    (void)argc;
    (void)argv;
}

#endif // CLUSTERFUZZLITE_HAVE_MSAN
