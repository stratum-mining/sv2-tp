// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>

#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <test/util/coverage.h>
#include <test/util/random.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/sanitizer.h>
#include <util/sock.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdio>
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
#include <tuple>
#include <utility>
#include <vector>

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define MEMORY_SANITIZER 1
#endif
#endif

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#endif

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION) && defined(__AFL_FUZZ_INIT)
__AFL_FUZZ_INIT();
#endif

extern const std::function<void(const std::string&)> G_TEST_LOG_FUN{};

const TranslateFn G_TRANSLATION_FUN{nullptr};

using util::sanitizer::GetEnvUnpoisoned;
using util::sanitizer::UnpoisonCString;

// The instrumented toolchain we ship to ClusterFuzzLite runners lacks the MSan
// interceptors that unpoison getenv() results, so avoid logging those strings.
static bool RunningUnderClusterFuzzLite()
{
    return GetEnvUnpoisoned("SV2_CLUSTERFUZZLITE") != nullptr;
}

static void EnsureMsanExternalSymbolizer(const std::string& symbolizer_path)
{
    const char* existing{GetEnvUnpoisoned("MSAN_OPTIONS")};
    if (existing != nullptr && std::strstr(existing, "external_symbolizer_path=") != nullptr) {
        return;
    }

    std::string new_opts{"external_symbolizer_path="};
    new_opts.append(symbolizer_path);
    if (existing != nullptr && existing[0] != '\0') {
        new_opts.push_back(':');
        new_opts.append(existing);
    }
    setenv("MSAN_OPTIONS", new_opts.c_str(), 1);
}

static void ExportSymbolizerEnv(const fs::path& symbolizer_path)
{
    const std::string sym{fs::PathToString(symbolizer_path)};
    setenv("LLVM_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("ASAN_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("MSAN_SYMBOLIZER_PATH", sym.c_str(), 1);
    setenv("UBSAN_SYMBOLIZER_PATH", sym.c_str(), 1);

    EnsureMsanExternalSymbolizer(sym);
}

static void MaybeConfigureSymbolizer(const char* argv0)
{
    // Currently only auto-configure when running under ClusterFuzzLite; other
    // environments can export these variables themselves if desired.
    if (!RunningUnderClusterFuzzLite()) return;
    if (argv0 == nullptr) return;
    if (GetEnvUnpoisoned("LLVM_SYMBOLIZER_PATH") != nullptr) return;

    try {
        UnpoisonCString(argv0);
        fs::path exe_path{argv0};
        if (exe_path.empty()) return;
        if (!exe_path.is_absolute()) {
            exe_path = fs::weakly_canonical(fs::path{fs::current_path()} / exe_path);
        }
        fs::path symbolizer_path{exe_path.parent_path()};
        symbolizer_path /= "llvm-symbolizer";
        if (!fs::exists(symbolizer_path) || !fs::is_regular_file(symbolizer_path)) return;

        ExportSymbolizerEnv(symbolizer_path);
    } catch (const fs::filesystem_error&) {
        // If we cannot discover the executable path, fall back to the caller-provided environment.
    }
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

static void SetArgs(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
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

extern const std::function<std::string()> G_TEST_GET_FULL_NAME{[]{
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
    // Some environments call LLVMFuzzerInitialize with null argv pointers; guard before
    // we try to derive the executable path for symbolizer discovery.
    if (argv != nullptr && *argv != nullptr && (*argv)[0] != nullptr) {
        MaybeConfigureSymbolizer((*argv)[0]);
    }
    SetArgs(*argc, *argv);
    initialize();
    return 0;
}

#if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
int main(int argc, char** argv)
{
    // Standalone execution also defends against missing argv entries before probing paths.
    if (argv != nullptr && argv[0] != nullptr) {
        MaybeConfigureSymbolizer(argv[0]);
    }
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
