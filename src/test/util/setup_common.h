// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SETUP_COMMON_H
#define BITCOIN_TEST_UTIL_SETUP_COMMON_H

#include <common/args.h> // IWYU pragma: export
#include <node/kernel_cache_sizes.h>
#include <node/kernel_context.h>
#include <node/caches.h>
#include <node/context.h> // IWYU pragma: export
#include <optional>
#include <ostream>
#include <primitives/transaction_identifier.h>
#include <stdexcept>
#include <test/util/net.h>
#include <test/util/random.h>
#include <util/chaintype.h> // IWYU pragma: export
#include <util/check.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>
#include <util/string.h>
#include <util/vector.h>

#include <functional>
#include <type_traits>
#include <vector>

class arith_uint256;
class FastRandomContext;
class uint160;
class uint256;

/** This is connected to the logger. Can be used to redirect logs to any other log */
extern const std::function<void(const std::string&)> G_TEST_LOG_FUN;

/** Retrieve the command line arguments. */
extern const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

/** Retrieve the unit test name. */
extern const std::function<std::string()> G_TEST_GET_FULL_NAME;

// Note: CENT removed (unused in surviving tests).

struct TestOpts {
    std::vector<const char*> extra_args{};
    bool coins_db_in_memory{true};
    bool block_tree_db_in_memory{true};
    bool setup_net{true};
    bool setup_validation_interface{true};
    bool min_validation_cache{false}; // Equivalent of -maxsigcachebytes=0
};

/** Basic testing setup.
 * This just configures logging, data dir and chain parameters.
 */
struct BasicTestingSetup {
    util::SignalInterrupt m_interrupt;
    node::NodeContext m_node; // keep as first member to be destructed last

    FastRandomContext m_rng;
    /** Seed the global RNG state and m_rng for testing and log the seed value. This affects all randomness, except GetStrongRandBytes(). */
    void SeedRandomForTest(SeedRand seed)
    {
        SeedRandomStateForTest(seed);
        m_rng.Reseed(GetRandHash());
    }

    explicit BasicTestingSetup(const ChainType chainType = ChainType::MAIN, TestOpts = {});
    ~BasicTestingSetup();

    fs::path m_path_root;
    fs::path m_path_lock;
    bool m_has_custom_datadir{false};
    /** @brief Test-specific arguments and settings.
     *
     * This member is intended to be the primary source of settings for code
     * being tested by unit tests. It exists to make tests more self-contained
     * and reduce reliance on global state.
     *
     * Usage guidelines:
     * 1. Prefer using m_args where possible in test code.
     * 2. If m_args is not accessible, use m_node.args as a fallback.
     * 3. Avoid direct references to gArgs in test code.
     *
     * Note: Currently, m_node.args points to gArgs for backwards
     * compatibility. In the future, it will point to m_args to further isolate
     * test environments.
     *
     * @see https://github.com/bitcoin/bitcoin/issues/25055 for additional context.
     */
    ArgsManager m_args;
};

/** Testing setup that performs all steps up until right before
 * ChainstateManager gets initialized. Meant for testing ChainstateManager
 * initialization behaviour.
 */
struct ChainTestingSetup : public BasicTestingSetup {
    kernel::CacheSizes m_kernel_cache_sizes{node::CalculateCacheSizes(m_args).kernel};
    bool m_coins_db_in_memory{true};
    bool m_block_tree_db_in_memory{true};
    std::function<void()> m_make_chainman{};

    explicit ChainTestingSetup(const ChainType chainType = ChainType::MAIN, TestOpts = {});
    ~ChainTestingSetup();

    // Supplies a chainstate, if one is needed
    void LoadVerifyActivateChainstate();
};

/** Testing setup that configures a complete environment.
 */
struct TestingSetup : public ChainTestingSetup {
    explicit TestingSetup(
        const ChainType chainType = ChainType::MAIN,
        TestOpts = {});
};

/** Identical to TestingSetup, but chain set to regtest */
struct RegTestingSetup : public TestingSetup {
    RegTestingSetup()
        : TestingSetup{ChainType::REGTEST} {}
};

/** Identical to TestingSetup, but chain set to testnet4 */
struct Testnet4Setup : public TestingSetup {
    Testnet4Setup()
        : TestingSetup{ChainType::TESTNET4} {}
};

class CBlock;
struct CMutableTransaction;
class CScript;

// Note: TestChain100Setup has been removed as it is unused by current tests.

/**
 * Make a test setup that has disk access to the debug.log file disabled. Can
 * be used in "hot loops", for example fuzzing or benchmarking.
 */
template <class T = const BasicTestingSetup>
std::unique_ptr<T> MakeNoLogFileContext(const ChainType chain_type = ChainType::REGTEST, TestOpts opts = {})
{
    opts.extra_args = Cat(
        {
            "-debuglogfile=0",
            "-debug=0",
        },
        opts.extra_args);

    return std::make_unique<T>(chain_type, opts);
}

class SocketTestingSetup : public BasicTestingSetup
{
public:
    explicit SocketTestingSetup();
    ~SocketTestingSetup();

    // Connect to the socket with a mock client (a DynSock) and send pre-loaded data.
    // Returns the I/O pipes from the mock client so we can read response datasent to it.
    std::shared_ptr<DynSock::Pipes> ConnectClient(const std::vector<uint8_t>& data);

private:
    // Save the original value of CreateSock here and restore it when the test ends.
    const decltype(CreateSock) m_create_sock_orig;

    // Queue of connected sockets returned by listening socket (represents network interface)
    std::shared_ptr<DynSock::Queue> m_accepted_sockets{std::make_shared<DynSock::Queue>()};
};

CBlock getBlock13b8a();

// Make types usable in BOOST_CHECK_* @{
namespace std {
template <typename T> requires std::is_enum_v<T>
inline std::ostream& operator<<(std::ostream& os, const T& e)
{
    return os << static_cast<std::underlying_type_t<T>>(e);
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const std::optional<T>& v)
{
    return v ? os << *v
             : os << "std::nullopt";
}
} // namespace std

std::ostream& operator<<(std::ostream& os, const arith_uint256& num);
std::ostream& operator<<(std::ostream& os, const uint160& num);
std::ostream& operator<<(std::ostream& os, const uint256& num);
std::ostream& operator<<(std::ostream& os, const Txid& txid);
std::ostream& operator<<(std::ostream& os, const Wtxid& wtxid);
// @}

/**
 * BOOST_CHECK_EXCEPTION predicates to check the specific validation error.
 * Use as
 * BOOST_CHECK_EXCEPTION(code that throws, exception type, HasReason("foo"));
 */
class HasReason
{
public:
    explicit HasReason(std::string_view reason) : m_reason(reason) {}
    bool operator()(std::string_view s) const { return s.find(m_reason) != std::string_view::npos; }
    bool operator()(const std::exception& e) const { return (*this)(e.what()); }

private:
    const std::string m_reason;
};

#endif // BITCOIN_TEST_UTIL_SETUP_COMMON_H
