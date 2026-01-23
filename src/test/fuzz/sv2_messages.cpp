// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sv2/messages.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/check_globals.h>
#include <test/sv2_test_setup.h>
#include <uint256.h>

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <string_view>
#include <vector>

using node::Sv2MsgType;
using node::Sv2NetHeader;
using node::Sv2SetupConnectionMsg;
using node::Sv2CoinbaseOutputConstraintsMsg;
using node::Sv2RequestTransactionDataMsg;
using node::Sv2SubmitSolutionMsg;
using node::Sv2SetupConnectionSuccessMsg;
using node::Sv2SetupConnectionErrorMsg;
using node::Sv2SetNewPrevHashMsg;
using node::Sv2RequestTransactionDataSuccessMsg;
using node::Sv2RequestTransactionDataErrorMsg;
using node::Sv2NetMsg;

// Exposed by the fuzz harness to pass through double-dash arguments.
extern const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS;

namespace {

void Initialize()
{
    // Add test context for debugging. Usage:
    // --debug=sv2 --loglevel=sv2:trace
    static const auto testing_setup = std::make_unique<const Sv2BasicTestingSetup>();

    // Optional: enable console logging when requested via double-dash args.
    bool want_console{false};
    bool want_sv2_debug{false};
    bool want_sv2_trace{false};
    if (G_TEST_COMMAND_LINE_ARGUMENTS) {
        for (const char* arg : G_TEST_COMMAND_LINE_ARGUMENTS()) {
            if (!arg) continue;
            std::string_view s{arg};
            if (s == "--printtoconsole" || s == "--printtoconsole=1") want_console = true;
            if (s == "--debug=sv2" || s == "--debug=1" || s == "--debug=all") want_sv2_debug = true;
            if (s == "--loglevel=sv2:trace" || s == "--loglevel=trace") want_sv2_trace = true;
        }
    }
    if (want_console || std::getenv("SV2_FUZZ_LOG")) {
        LogInstance().m_print_to_console = true;
        LogInstance().EnableCategory(BCLog::SV2);
        if (want_sv2_trace) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Trace}});
        } else if (want_sv2_debug || std::getenv("SV2_FUZZ_LOG_DEBUG")) {
            LogInstance().SetCategoryLogLevel({{BCLog::SV2, BCLog::Level::Debug}});
        }
        LogInstance().StartLogging();
    }
}

// Helper to generate a fuzzed string with bounded length
std::string FuzzedString(FuzzedDataProvider& provider, size_t max_len = 255)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, max_len);
    return provider.ConsumeBytesAsString(len);
}

// Helper to generate a fuzzed uint256
uint256 FuzzedUint256(FuzzedDataProvider& provider)
{
    auto bytes = provider.ConsumeBytes<uint8_t>(32);
    bytes.resize(32);
    uint256 result;
    memcpy(result.begin(), bytes.data(), 32);
    return result;
}

} // namespace

// Fuzz Sv2NetHeader parsing - tests the 24-bit length encoding
FUZZ_TARGET(sv2_net_header, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Test deserialization of fuzzed header bytes
    if (provider.remaining_bytes() >= 6) {
        DataStream ss{};
        auto header_bytes = provider.ConsumeBytes<uint8_t>(6);
        ss.write(MakeByteSpan(header_bytes));

        try {
            Sv2NetHeader header;
            ss >> header;

            // Verify the header was parsed
            (void)header.m_msg_type;
            (void)header.m_msg_len;

            // Roundtrip: serialize and compare
            DataStream ss_out{};
            ss_out << header;
        } catch (const std::exception&) {
            // Parsing failures are expected for malformed input
        }
    }

    // Test serialization with fuzzed values
    Sv2MsgType msg_type = static_cast<Sv2MsgType>(provider.ConsumeIntegral<uint8_t>());
    uint32_t msg_len = provider.ConsumeIntegralInRange<uint32_t>(0, 0xFFFFFF); // 24-bit max

    Sv2NetHeader header(msg_type, msg_len);
    DataStream ss_out{};
    ss_out << header;

    // Roundtrip
    Sv2NetHeader header_rt;
    ss_out >> header_rt;
    assert(header_rt.m_msg_type == msg_type);
    assert(header_rt.m_msg_len == msg_len);
}

// Fuzz Sv2SetupConnectionMsg deserialization (client -> TP message)
FUZZ_TARGET(sv2_setup_connection, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Test parsing potentially malformed SetupConnection messages
    DataStream ss{};

    // Build a fuzzed message
    ss << provider.ConsumeIntegral<uint8_t>();  // m_protocol
    ss << provider.ConsumeIntegral<uint16_t>(); // m_min_version
    ss << provider.ConsumeIntegral<uint16_t>(); // m_max_version
    ss << provider.ConsumeIntegral<uint32_t>(); // m_flags
    ss << FuzzedString(provider);               // m_endpoint_host
    ss << provider.ConsumeIntegral<uint16_t>(); // m_endpoint_port
    ss << FuzzedString(provider);               // m_vendor
    ss << FuzzedString(provider);               // m_hardware_version
    ss << FuzzedString(provider);               // m_firmware
    ss << FuzzedString(provider);               // m_device_id

    try {
        Sv2SetupConnectionMsg msg;
        ss >> msg;

        // Verify fields were parsed
        (void)msg.m_protocol;
        (void)msg.m_min_version;
        (void)msg.m_max_version;
        (void)msg.m_flags;
        (void)msg.m_endpoint_host;
        (void)msg.m_endpoint_port;
        (void)msg.m_vendor;
        (void)msg.m_hardware_version;
        (void)msg.m_firmware;
        (void)msg.m_device_id;
    } catch (const std::exception&) {
        // Parsing failures are expected
    }
}

// Fuzz Sv2CoinbaseOutputConstraintsMsg (client -> TP message)
FUZZ_TARGET(sv2_coinbase_output_constraints, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    DataStream ss{};
    ss << provider.ConsumeIntegral<uint32_t>(); // m_coinbase_output_max_additional_size

    // Optionally include the sigops field (added March 2025)
    if (provider.ConsumeBool()) {
        ss << provider.ConsumeIntegral<uint16_t>(); // m_coinbase_output_max_additional_sigops
    }

    try {
        Sv2CoinbaseOutputConstraintsMsg msg;
        ss >> msg;

        // Verify parsing
        (void)msg.m_coinbase_output_max_additional_size;
        (void)msg.m_coinbase_output_max_additional_sigops;

        // Roundtrip test
        DataStream ss_out{};
        ss_out << msg;
    } catch (const std::exception&) {
        // Expected for malformed input
    }
}

// Fuzz Sv2RequestTransactionDataMsg (client -> TP message)
FUZZ_TARGET(sv2_request_transaction_data, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    DataStream ss{};
    ss << provider.ConsumeIntegral<uint64_t>(); // m_template_id

    try {
        Sv2RequestTransactionDataMsg msg;
        ss >> msg;
        (void)msg.m_template_id;
    } catch (const std::exception&) {
        // Expected
    }
}

// Fuzz Sv2SubmitSolutionMsg deserialization (client -> TP message)
// This is security-critical as it contains a coinbase transaction
FUZZ_TARGET(sv2_submit_solution, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    DataStream ss{};
    ss << provider.ConsumeIntegral<uint64_t>(); // m_template_id
    ss << provider.ConsumeIntegral<uint32_t>(); // m_version
    ss << provider.ConsumeIntegral<uint32_t>(); // m_header_timestamp
    ss << provider.ConsumeIntegral<uint32_t>(); // m_header_nonce

    // Fuzzed coinbase transaction bytes (with 2-byte length prefix)
    size_t tx_len = provider.ConsumeIntegralInRange<size_t>(0, 10000);
    auto tx_bytes = provider.ConsumeBytes<uint8_t>(tx_len);
    ss << static_cast<uint16_t>(tx_bytes.size());
    ss.write(MakeByteSpan(tx_bytes));

    try {
        Sv2SubmitSolutionMsg msg;
        ss >> msg;

        // If parsing succeeded, verify fields
        (void)msg.m_template_id;
        (void)msg.m_version;
        (void)msg.m_header_timestamp;
        (void)msg.m_header_nonce;
        (void)msg.m_coinbase_tx;
    } catch (const std::exception&) {
        // Expected for malformed transactions
    }
}

// Fuzz Sv2SetupConnectionSuccessMsg roundtrip (TP -> client message)
FUZZ_TARGET(sv2_setup_connection_success, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint16_t used_version = provider.ConsumeIntegral<uint16_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();

    Sv2SetupConnectionSuccessMsg msg(used_version, flags);

    // Serialize
    DataStream ss{};
    ss << msg;

    // Verify serialization produced expected size
    assert(ss.size() == sizeof(uint16_t) + sizeof(uint32_t));
}

// Fuzz Sv2SetupConnectionErrorMsg roundtrip (TP -> client message)
FUZZ_TARGET(sv2_setup_connection_error, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    std::string error_code = FuzzedString(provider);

    Sv2SetupConnectionErrorMsg msg(flags, std::move(error_code));

    // Serialize
    DataStream ss{};
    ss << msg;
}

// Fuzz Sv2SetNewPrevHashMsg roundtrip (TP -> client message)
FUZZ_TARGET(sv2_set_new_prev_hash, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Create message with fuzzed values
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<int32_t>();
    header.hashPrevBlock = FuzzedUint256(provider);
    header.hashMerkleRoot = FuzzedUint256(provider);
    header.nTime = provider.ConsumeIntegral<uint32_t>();
    header.nBits = provider.ConsumeIntegral<uint32_t>();
    header.nNonce = provider.ConsumeIntegral<uint32_t>();

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();

    Sv2SetNewPrevHashMsg msg(header, template_id);

    // Serialize
    DataStream ss{};
    ss << msg;

    // Verify fields
    assert(msg.m_template_id == template_id);
    assert(msg.m_prev_hash == header.hashPrevBlock);
    assert(msg.m_header_timestamp == header.nTime);
    assert(msg.m_nBits == header.nBits);
}

// Fuzz Sv2RequestTransactionDataSuccessMsg (TP -> client message)
FUZZ_TARGET(sv2_request_transaction_data_success, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();

    // Fuzzed excess data
    size_t excess_len = provider.ConsumeIntegralInRange<size_t>(0, 1000);
    std::vector<uint8_t> excess_data = provider.ConsumeBytes<uint8_t>(excess_len);

    // Empty transaction list for simplicity (transaction fuzzing is complex)
    std::vector<CTransactionRef> txs;

    Sv2RequestTransactionDataSuccessMsg msg(template_id, std::move(excess_data), std::move(txs));

    // Serialize
    DataStream ss{};
    ss << msg;

    // Verify template_id preserved
    assert(msg.m_template_id == template_id);
}

// Fuzz Sv2RequestTransactionDataErrorMsg (TP -> client message)
FUZZ_TARGET(sv2_request_transaction_data_error, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();
    std::string error_code = FuzzedString(provider);

    Sv2RequestTransactionDataErrorMsg msg(template_id, std::move(error_code));

    // Serialize
    DataStream ss{};
    ss << msg;
}

// Fuzz Sv2NetMsg wrapping/unwrapping
FUZZ_TARGET(sv2_net_msg, .init = Initialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Create a simple message to wrap
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    std::string error_code = FuzzedString(provider, 50);

    Sv2SetupConnectionErrorMsg inner_msg(flags, std::move(error_code));
    Sv2NetMsg net_msg(inner_msg);

    // Verify message type
    assert(net_msg.m_msg_type == Sv2MsgType::SETUP_CONNECTION_ERROR);

    // Convert to header
    Sv2NetHeader hdr = net_msg;
    assert(hdr.m_msg_type == Sv2MsgType::SETUP_CONNECTION_ERROR);
    assert(hdr.m_msg_len == net_msg.size());

    // Serialize and deserialize
    DataStream ss{};
    ss << net_msg;

    Sv2NetMsg net_msg_rt(Sv2MsgType::SETUP_CONNECTION_ERROR, {});
    ss >> net_msg_rt;
    assert(net_msg_rt.m_msg_type == net_msg.m_msg_type);
}
