// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_test_setup.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <init/common.h>
#include <key.h>
#include <logging.h>
#include <util/chaintype.h>
#include <util/result.h>
#include <util/string.h>
#include <util/time.h>
#include <array>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

// Provided by main.cpp
extern std::function<void(const std::string&)> G_TEST_LOG_FUN;
extern std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

Sv2BasicTestingSetup::Sv2BasicTestingSetup()
{
    // A previous fixture's constructor may have thrown before clearing its args.
    gArgs.ClearArgs();

    // Select a default chain for tests to satisfy BaseParams() users.
    SelectBaseParams(ChainType::REGTEST);

    // Default mock time anchored to Bitcoin genesis so certificate helpers see a realistic clock.
    SetMockTime(TEST_GENESIS_TIME);

    // Create an isolated temporary datadir for this test process.
    const auto micros = count_microseconds(Now<SteadyMicroseconds>().time_since_epoch());
    const std::string subdir = util::Join(std::array<std::string, 2>{"sv2_tests", util::ToString(micros)}, "");
    fs::path tmp = fs::path(fs::temp_directory_path());
    m_tmp_root = tmp / fs::u8path(subdir);
    fs::create_directories(m_tmp_root);

    // Set datadir arg so any code that writes under datadir uses the temp path.
    gArgs.ForceSetArg("-datadir", fs::PathToString(m_tmp_root));

    // Set up logging like sv2-tp does. Lines go to G_TEST_LOG_FUN, which only
    // prints them when DEBUG_LOG_OUT is passed (see main.cpp). Logging options
    // can be appended after `--`, e.g.:
    // test_sv2 -t sv2_template_provider_tests -- -loglevel=sv2:debug DEBUG_LOG_OUT
    init::AddLoggingArgs(gArgs);
    std::vector<const char*> arguments{"dummy", "-printtoconsole=0", "-debuglogfile=0", "-logsourcelocations", "-logtimemicros", "-logthreadnames", "-debug", "-loglevel=trace"};
    if (G_TEST_COMMAND_LINE_ARGUMENTS) {
        for (const char* arg : G_TEST_COMMAND_LINE_ARGUMENTS()) arguments.push_back(arg);
    }
    std::string error;
    if (!gArgs.ParseParameters(arguments.size(), arguments.data(), error)) throw std::runtime_error{error};
    if (!gArgs.ReadConfigFiles(error, /*ignore_invalid_keys=*/true)) throw std::runtime_error{error};
    init::SetLoggingOptions(gArgs);
    if (const auto res{init::SetLoggingCategories(gArgs)}; !res) throw std::runtime_error{util::ErrorString(res).original};
    if (const auto res{init::SetLoggingLevel(gArgs)}; !res) throw std::runtime_error{util::ErrorString(res).original};
    if (G_TEST_LOG_FUN) LogInstance().PushBackCallback(G_TEST_LOG_FUN);
    if (!init::StartLogging(gArgs)) throw std::runtime_error{"StartLogging failed"};

    // Initialize ECC context needed by key and crypto operations used in tests.
    m_ecc = std::make_unique<ECC_Context>();
}

Sv2BasicTestingSetup::~Sv2BasicTestingSetup()
{
    LogInstance().DisconnectTestLogger();
    gArgs.ClearArgs();
    SetMockTime(std::chrono::seconds{0});

    try {
        fs::remove_all(m_tmp_root);
    } catch (const std::exception&) {
        // Best effort cleanup.
    }
    m_ecc.reset();
}

node::Sv2NetMsg TestSubmitSolutionMsg()
{
    // Same payload as Sv2SubmitSolution_test in sv2_messages_tests.cpp
    std::vector<uint8_t> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // template_id
        0x02, 0x00, 0x00, 0x00,                           // version
        0x97, 0x3c, 0x0e, 0x63,                           // ntime
        0xff, 0xff, 0x7f, 0x03,                           // nonce
        0x5d, 0x00,                                       // 2 byte length of coinbase_tx
        0x2, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, // coinbase_tx
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff,
        0xff, 0x22, 0x1, 0x18, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff,
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x16,
        0x0, 0x14, 0x53, 0x12, 0x60, 0xaa, 0x2a, 0x19, 0x9e,
        0x22, 0x8c, 0x53, 0x7d, 0xfa, 0x42, 0xc8, 0x2b, 0xea,
        0x2c, 0x7c, 0x1f, 0x4d, 0x0, 0x0, 0x0, 0x0};

    return node::Sv2NetMsg{node::Sv2MsgType::SUBMIT_SOLUTION, std::move(bytes)};
}

CMutableTransaction TestProposeTemplateCoinbase()
{
    CMutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 17 << std::vector<unsigned char>(8, 0x00);
    coinbase.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(32, 0x00));
    coinbase.vout.resize(2);
    coinbase.vout[0].nValue = 50 * COIN;
    coinbase.vout[0].scriptPubKey = CScript() << OP_TRUE;
    coinbase.vout[1].nValue = 0;
    coinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(36, 0xaa);
    return coinbase;
}

node::Sv2NetMsg TestProposeTemplateMsg(uint32_t request_id, const std::vector<Wtxid>& wtxids)
{
    std::vector<unsigned char> coinbase;
    VectorWriter{coinbase, 0, TX_WITH_WITNESS(TestProposeTemplateCoinbase())};
    // nVersion, marker and flag, input count, prevout, scriptSig length,
    // BIP34 height push, extranonce push opcode
    constexpr size_t extranonce_start{4 + 2 + 1 + 36 + 1 + 2 + 1};
    constexpr size_t extranonce_len{8};

    DataStream ss{};
    ss << request_id
       << uint32_t{0x20000000}; // version
    node::WriteB0_64K(ss, std::span{coinbase}.first(extranonce_start));
    node::WriteB0_64K(ss, std::span{coinbase}.subspan(extranonce_start + extranonce_len));
    ss << static_cast<uint16_t>(wtxids.size());
    for (const Wtxid& wtxid : wtxids) ss << wtxid;
    node::WriteB0_64K(ss, {}); // excess_data

    std::vector<uint8_t> bytes(ss.size());
    ss >> MakeWritableByteSpan(bytes);
    return node::Sv2NetMsg{node::Sv2MsgType::PROPOSE_TEMPLATE, std::move(bytes)};
}

node::Sv2NetMsg TestProvideMissingTransactionsMsg(uint32_t request_id, const std::vector<CTransactionRef>& transaction_list)
{
    DataStream ss{};
    ss << request_id
       << static_cast<uint16_t>(transaction_list.size());
    for (const CTransactionRef& tx : transaction_list) {
        std::vector<unsigned char> raw;
        VectorWriter{raw, 0, TX_WITH_WITNESS(*tx)};
        const node::u24_t len{uint8_t(raw.size()), uint8_t(raw.size() >> 8), uint8_t(raw.size() >> 16)};
        ss << len;
        ss.write(MakeByteSpan(raw));
    }

    std::vector<uint8_t> bytes(ss.size());
    ss >> MakeWritableByteSpan(bytes);
    return node::Sv2NetMsg{node::Sv2MsgType::PROVIDE_MISSING_TRANSACTIONS_SUCCESS, std::move(bytes)};
}

Sv2LogCapture::Sv2LogCapture()
{
    m_callback = LogInstance().PushBackCallback([this](const std::string& line) {
        StdLockGuard lock(m_mutex);
        m_lines.push_back(line);
    });
}

Sv2LogCapture::~Sv2LogCapture()
{
    LogInstance().DeleteCallback(m_callback);
}

bool Sv2LogCapture::WaitFor(std::string_view needle, std::chrono::milliseconds timeout)
{
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
        {
            StdLockGuard lock(m_mutex);
            for (const auto& line : m_lines) {
                if (line.find(needle) != std::string::npos) return true;
            }
        }
        if (std::chrono::steady_clock::now() - start > timeout) return false;
        UninterruptibleSleep(std::chrono::milliseconds{5});
    }
}
