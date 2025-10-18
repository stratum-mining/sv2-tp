// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>

#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <test/util/clusterfuzzlite.h>
#include <test/util/coverage.h>
#include <test/util/random.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/sanitizer.h>
#include <util/sock.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define MEMORY_SANITIZER 1
#endif
#endif

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#if defined(__has_include)
#if __has_include(<sanitizer/sanitizer_flags.h>)
#define BITCOIN_HAVE_SANITIZER_COMMON_FLAGS 1
#include <sanitizer/sanitizer_flags.h>
#endif
#endif
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && defined(__AFL_FUZZ_INIT)
__AFL_FUZZ_INIT();
#endif

extern const std::function<void(const std::string&)> G_TEST_LOG_FUN{};

const TranslateFn G_TRANSLATION_FUN{nullptr};

using util::sanitizer::GetEnvUnpoisoned;
using util::sanitizer::Unpoison;
using util::sanitizer::UnpoisonArray;
using util::sanitizer::UnpoisonCString;
using util::sanitizer::UnpoisonMemory;

static void UnpoisonPath(fs::path& path)
{
    Unpoison(path);
#ifdef MEMORY_SANITIZER
    const auto& native{path.native()};
    const auto count{native.size() + 1};
    if (count != 0) {
        UnpoisonMemory(native.c_str(), count * sizeof(fs::path::value_type));
    }
#endif
}

#ifdef MEMORY_SANITIZER
static bool MsanSymbolizerDebuggingEnabled()
{
    static const bool kDebug = [] {
        const char* const debug_env{GetEnvUnpoisoned("SV2_DEBUG_MSAN_SYMBOLIZER")};
        return debug_env != nullptr && debug_env[0] != '\0';
    }();
    return kDebug;
}
#else
static bool MsanSymbolizerDebuggingEnabled() { return false; }
#endif

#ifdef MEMORY_SANITIZER
static void LogMsanSymbolizerState(const char* context)
{
    if (!RunningUnderClusterFuzzLite() || !MsanSymbolizerDebuggingEnabled()) return;

    const char* const llvm_symbolizer{GetEnvUnpoisoned("LLVM_SYMBOLIZER_PATH")};
    const char* const msan_options{GetEnvUnpoisoned("MSAN_OPTIONS")};
    std::fprintf(stderr, "[cfl] %s: LLVM_SYMBOLIZER_PATH='%s'\n", context, (llvm_symbolizer != nullptr && llvm_symbolizer[0] != '\0') ? llvm_symbolizer : "<unset>");
    std::fprintf(stderr, "[cfl] %s: MSAN_OPTIONS='%s'\n", context, (msan_options != nullptr && msan_options[0] != '\0') ? msan_options : "<unset>");
#if defined(BITCOIN_HAVE_SANITIZER_COMMON_FLAGS)
    const auto* const flags{__sanitizer::common_flags()};
    const char* const cached{(flags != nullptr) ? flags->external_symbolizer_path : nullptr};
    std::fprintf(stderr, "[cfl] %s: cached external_symbolizer_path='%s'\n", context, (cached != nullptr && cached[0] != '\0') ? cached : "<empty>");
#else
    std::fprintf(stderr, "[cfl] %s: cached external_symbolizer_path='<unavailable>'\n", context);
#endif
}
#else
static void LogMsanSymbolizerState(const char*) {}
#endif

// When ClusterFuzzLite bundles a harness, MSan caches its symbolizer path
// before our overrides land in MSAN_OPTIONS. Re-exec once so the runtime
// observes the updated environment before fuzzing proceeds.
static void MaybeReexecForMsanSymbolizer(int argc, char** argv)
{
#if defined(MEMORY_SANITIZER) && defined(__linux__)
    if (!RunningUnderClusterFuzzLite()) return;
    if (argv == nullptr || argc <= 0 || argv[0] == nullptr) return;

    // Allow ad-hoc debugging to keep the legacy single-process flow.
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
    // Always override so packaged harnesses don't inherit stale ClusterFuzzLite paths.
    // The build stage executes the harness in-place (system /usr/local/ still exists), but
    // "bad build" replays run from a bundle that only ships our copied symbolizer.

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
            if (!token.empty() && token.rfind("external_symbolizer_path=", 0) != 0) {
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
// MSan builds run on Linux GA runners; check executable bits directly.
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
// Windows lacks X_OK; rely on filesystem queries when we ever enable CIFuzz there.
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

// Environment variables may be set by CI; trust them only after unpoisoning and probing.
static bool TryExportSymbolizerFromEnv(const char* configured_symbolizer)
{
    if (configured_symbolizer == nullptr || configured_symbolizer[0] == '\0') return false;
    const std::size_t configured_len{std::strlen(configured_symbolizer)};
    if (configured_len == 0) return false;
    UnpoisonMemory(configured_symbolizer, configured_len + 1);

    std::string configured{configured_symbolizer};
    return TryExportSymbolizerFromUtf8(configured);
}

static void MaybeConfigureSymbolizer(int argc, char** argv)
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
        // If we cannot discover the executable path, fall back to the caller-provided environment.
        log_context = "MaybeConfigureSymbolizer(fs-exception)";
    }

    LogMsanSymbolizerState(log_context);
    MaybeReexecForMsanSymbolizer(argc, argv);
}

static constexpr char FuzzTargetPlaceholder[] = "d6f1a2b39c4e5d7a8b9c0d1e2f30415263748596a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00fedcba9876543210a0b1c2d3";

/**
 * A copy of the command line arguments that start with `--`.
 * First `LLVMFuzzerInitialize()` is called, which saves the arguments to `g_args`.
 * Later, depending on the fuzz test, `G_TEST_COMMAND_LINE_ARGUMENTS()` may be
 * called by `BasicTestingSetup` constructor to fetch those arguments and store
 * them in `BasicTestingSetup::m_node::args`.
 */
static std::vector<const char*> g_args;

static void SetArgs(int argc, char** argv)
{
    if (argv == nullptr || argc <= 0) return;
    UnpoisonArray(argv, static_cast<std::size_t>(argc));
    if (argv[0] != nullptr) {
        Unpoison(argv[0]);
        UnpoisonCString(argv[0]);
    }
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == nullptr) continue;
        Unpoison(argv[i]);
        UnpoisonCString(argv[i]);
        // Only take into account arguments that start with `--`. The others are for the fuzz engine:
        // `fuzz -runs=1 fuzz_corpora/address_deserialize_v2 --checkaddrman=5`
        if (strlen(argv[i]) > 2 && argv[i][0] == '-' && argv[i][1] == '-') {
            g_args.push_back(argv[i]);
        }
    }
}

extern const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return g_args;
};

struct FuzzTarget {
    const TypeTestOneInput test_one_input;
    const FuzzTargetOptions opts;
};

auto& FuzzTargets()
{
    static std::map<std::string, FuzzTarget, std::less<>> g_fuzz_targets;
    return g_fuzz_targets;
}

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target, FuzzTargetOptions opts)
{
    std::string owned_name{name};
#ifdef MEMORY_SANITIZER
    __msan_unpoison(&owned_name, sizeof(owned_name));
    const auto name_length{name.size()};
    const auto bytes_to_unpoison = name_length + 1U; // include trailing null terminator
    if (bytes_to_unpoison != 0) {
        __msan_unpoison(owned_name.data(), bytes_to_unpoison);
    }
#endif
    const auto [it, ins]{FuzzTargets().emplace(std::move(owned_name), FuzzTarget{target, opts})};
    Assert(ins);
}

static std::string_view g_fuzz_target;
static const TypeTestOneInput* g_test_one_input{nullptr};
static void test_one_input(FuzzBufferType buffer)
{
    (*Assert(g_test_one_input))(buffer);
}

extern const std::function<std::string()> G_TEST_GET_FULL_NAME{[] {
    return std::string{g_fuzz_target};
}};

static void initialize()
{
    if (RunningUnderClusterFuzzLite()) {
        LogInstance().SetLogLevel(BCLog::Level::Warning);
    }
    // By default, make the RNG deterministic with a fixed seed. This will affect all
    // randomness during the fuzz test, except:
    // - GetStrongRandBytes(), which is used for the creation of private key material.
    // - Randomness obtained before this call in g_rng_temp_path_init
    SeedRandomStateForTest(SeedRand::ZEROS);

    // Set time to the genesis block timestamp for deterministic initialization.
    SetMockTime(1231006505);

    // Terminate immediately if a fuzzing harness ever tries to create a socket.
    // Individual tests can override this by pointing CreateSock to a mocked alternative.
    CreateSock = [](int, int, int) -> std::unique_ptr<Sock> { std::terminate(); };

    // Terminate immediately if a fuzzing harness ever tries to perform a DNS lookup.
    g_dns_lookup = [](const std::string& name, bool allow_lookup) {
        if (allow_lookup) {
            std::terminate();
        }
        return WrappedGetAddrInfo(name, false);
    };

    const char* env_fuzz{GetEnvUnpoisoned("FUZZ")};
    const char* env_print_targets{GetEnvUnpoisoned("PRINT_ALL_FUZZ_TARGETS_AND_ABORT")};
    const char* env_write_targets{GetEnvUnpoisoned("WRITE_ALL_FUZZ_TARGETS_AND_ABORT")};
    const bool listing_mode{env_print_targets != nullptr || env_write_targets != nullptr};
    static std::string g_copy;
    g_copy.assign((env_fuzz != nullptr && env_fuzz[0] != '\0') ? env_fuzz : FuzzTargetPlaceholder);
    g_fuzz_target = std::string_view{g_copy.data(), g_copy.size()};

    bool should_exit{false};
    if (env_print_targets != nullptr) {
        for (const auto& [name, t] : FuzzTargets()) {
            if (t.opts.hidden) continue;
            std::cout << name << std::endl;
        }
        should_exit = true;
    }
    if (env_write_targets != nullptr) {
        const char* out_path_env{env_write_targets};
        const bool running_under_cfl{RunningUnderClusterFuzzLite()};
        const char* out_path_cstr{running_under_cfl ? "/work/fuzz_targets.txt" : out_path_env};
        if (!running_under_cfl) {
            std::cout << "Writing all fuzz target names to '" << out_path_cstr << "'." << std::endl;
        }
        if (FILE* out_file = std::fopen(out_path_cstr, "wb")) {
            for (const auto& [name, t] : FuzzTargets()) {
                if (t.opts.hidden) continue;
                std::fwrite(name.data(), 1, name.size(), out_file);
                std::fputc('\n', out_file);
            }
            std::fclose(out_file);
        } else {
            std::perror("fopen fuzz target list");
        }
        should_exit = true;
    }
    if (should_exit) {
        std::exit(EXIT_SUCCESS);
    }

    const std::string target_name{g_fuzz_target};
    const auto it = FuzzTargets().find(target_name);
    if (it == FuzzTargets().end()) {
        if (!listing_mode && (env_fuzz == nullptr || env_fuzz[0] == '\0')) {
            std::cerr << "Must select fuzz target with the FUZZ env var." << std::endl;
            std::cerr << "Hint: Set the PRINT_ALL_FUZZ_TARGETS_AND_ABORT=1 env var to see all compiled targets." << std::endl;
        } else {
            std::cerr << "No fuzz target compiled for " << g_fuzz_target << "." << std::endl;
        }
        std::exit(EXIT_FAILURE);
    }
    if constexpr (!G_FUZZING_BUILD && !G_ABORT_ON_FAILED_ASSUME) {
        std::cerr << "Must compile with -DBUILD_FOR_FUZZING=ON or in Debug mode to execute a fuzz target." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (!EnableFuzzDeterminism()) {
        if (GetEnvUnpoisoned("FUZZ_NONDETERMINISM")) {
            std::cerr << "Warning: FUZZ_NONDETERMINISM env var set, results may be inconsistent with fuzz build" << std::endl;
        } else {
            g_enable_dynamic_fuzz_determinism = true;
            assert(EnableFuzzDeterminism());
        }
    }
    Assert(!g_test_one_input);
    g_test_one_input = &it->second.test_one_input;
    it->second.opts.init();

    ResetCoverageCounters();
}

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
static bool read_stdin(std::vector<uint8_t>& data)
{
    std::istream::char_type buffer[1024];
    std::streamsize length;
    while ((std::cin.read(buffer, 1024), length = std::cin.gcount()) > 0) {
        data.insert(data.end(), buffer, buffer + length);
    }
    return length == 0;
}
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && !defined(__AFL_LOOP)
static bool read_file(fs::path p, std::vector<uint8_t>& data)
{
    uint8_t buffer[1024];
    FILE* f = fsbridge::fopen(p, "rb");
    if (f == nullptr) return false;
    do {
        const size_t length = fread(buffer, sizeof(uint8_t), sizeof(buffer), f);
        if (ferror(f)) return false;
        data.insert(data.end(), buffer, buffer + length);
    } while (!feof(f));
    fclose(f);
    return true;
}
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && !defined(__AFL_LOOP)
static fs::path g_input_path;
void signal_handler(int signal)
{
    if (signal == SIGABRT) {
        std::cerr << "Error processing input " << g_input_path << std::endl;
    } else {
        std::cerr << "Unexpected signal " << signal << " received\n";
    }
    std::_Exit(EXIT_FAILURE);
}
#endif

// This function is used by libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    test_one_input({data, size});
    return 0;
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    int arg_count{0};
    if (argc != nullptr) {
        util::sanitizer::UnpoisonMemory(argc, sizeof(*argc));
        arg_count = *argc;
    }

    char** argv_values{nullptr};
    if (argv != nullptr) {
        util::sanitizer::UnpoisonMemory(argv, sizeof(*argv));
        argv_values = *argv;
        if (argv_values != nullptr && arg_count > 0) {
            UnpoisonArray(argv_values, static_cast<std::size_t>(arg_count));
        }
    }

    SetArgs(arg_count, argv_values);

    MaybeConfigureSymbolizer(arg_count, argv_values);
    initialize();
    return 0;
}

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
int main(int argc, char** argv)
{
    if (argv != nullptr && argc > 0) {
        UnpoisonArray(argv, static_cast<std::size_t>(argc));
    }
    // Standalone execution also defends against missing argv entries before probing paths.
    if (argv != nullptr && argv[0] != nullptr) {
        Unpoison(argv[0]);
        UnpoisonCString(argv[0]);
    }
    MaybeConfigureSymbolizer(argc, argv);
    initialize();
#ifdef __AFL_LOOP
    // Enable AFL persistent mode. Requires compilation using afl-clang-fast++.
    // See fuzzing.md for details.
    const uint8_t* buffer = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t buffer_len = __AFL_FUZZ_TESTCASE_LEN;
        test_one_input({buffer, buffer_len});
    }
#else
    std::vector<uint8_t> buffer;
    if (argc <= 1) {
        if (!read_stdin(buffer)) {
            return 0;
        }
        test_one_input(buffer);
        return 0;
    }
    std::signal(SIGABRT, signal_handler);
    const auto start_time{Now<SteadySeconds>()};
    int tested = 0;
    for (int i = 1; i < argc; ++i) {
        fs::path input_path(*(argv + i));
        if (fs::is_directory(input_path)) {
            std::vector<fs::path> files;
            for (fs::directory_iterator it(input_path); it != fs::directory_iterator(); ++it) {
                if (!fs::is_regular_file(it->path())) continue;
                files.emplace_back(it->path());
            }
            std::ranges::shuffle(files, std::mt19937{std::random_device{}()});
            for (const auto& input_path : files) {
                g_input_path = input_path;
                Assert(read_file(input_path, buffer));
                test_one_input(buffer);
                ++tested;
                buffer.clear();
            }
        } else {
            g_input_path = input_path;
            Assert(read_file(input_path, buffer));
            test_one_input(buffer);
            ++tested;
            buffer.clear();
        }
    }
    const auto end_time{Now<SteadySeconds>()};
    if (!RunningUnderClusterFuzzLite()) {
        std::cout << g_fuzz_target << ": succeeded against " << tested << " files in " << count_seconds(end_time - start_time) << "s." << std::endl;
    }
#endif
    return 0;
}
#endif
