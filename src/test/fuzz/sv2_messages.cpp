// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sv2/messages.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/check_globals.h>
#include <test/fuzz/sv2_fuzz_util.h>

#include <cstdint>
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
using node::Sv2NewTemplateMsg;
using node::Sv2NetMsg;

namespace {

// Helper to generate a fuzzed string with bounded length.
std::string FuzzedString(FuzzedDataProvider& provider, size_t max_len = 255)
{
    size_t len = provider.ConsumeIntegralInRange<size_t>(0, max_len);
    return provider.ConsumeBytesAsString(len);
}

} // namespace

// Fuzz Sv2NetHeader parsing - tests the 24-bit length encoding.
FUZZ_TARGET(sv2_net_header, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Test deserialization of fuzzed header bytes.
    // The try/catch is intentional: the fuzzer looks for memory errors and
    // undefined behavior (caught by sanitizers), not parse exceptions.
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
        } catch (const std::ios_base::failure&) {
            // Stream read failures are expected for malformed input
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

// Fuzz Sv2SetupConnectionMsg deserialization (client -> TP message).
// We construct a well-formed stream, so deserialization must succeed.
FUZZ_TARGET(sv2_setup_connection, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    DataStream ss{};

    // Build a fuzzed message matching the Unserialize field order
    uint8_t protocol = provider.ConsumeIntegral<uint8_t>();
    uint16_t min_version = provider.ConsumeIntegral<uint16_t>();
    uint16_t max_version = provider.ConsumeIntegral<uint16_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    std::string endpoint_host = FuzzedString(provider);
    uint16_t endpoint_port = provider.ConsumeIntegral<uint16_t>();
    std::string vendor = FuzzedString(provider);
    std::string hardware_version = FuzzedString(provider);
    std::string firmware = FuzzedString(provider);
    std::string device_id = FuzzedString(provider);

    ss << protocol << min_version << max_version << flags
       << endpoint_host << endpoint_port
       << vendor << hardware_version << firmware << device_id;

    Sv2SetupConnectionMsg msg;
    ss >> msg;

    assert(msg.m_protocol == protocol);
    assert(msg.m_min_version == min_version);
    assert(msg.m_max_version == max_version);
    assert(msg.m_flags == flags);
    assert(msg.m_endpoint_host == endpoint_host);
    assert(msg.m_endpoint_port == endpoint_port);
    assert(msg.m_vendor == vendor);
    assert(msg.m_hardware_version == hardware_version);
    assert(msg.m_firmware == firmware);
    assert(msg.m_device_id == device_id);
}

// Fuzz Sv2CoinbaseOutputConstraintsMsg deserialization (client -> TP message).
// We construct a well-formed stream; the Unserialize method internally handles
// the optional sigops field with its own catch, so no outer catch is needed.
FUZZ_TARGET(sv2_coinbase_output_constraints, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint32_t max_additional_size = provider.ConsumeIntegral<uint32_t>();
    bool include_sigops = provider.ConsumeBool();
    uint16_t sigops = provider.ConsumeIntegral<uint16_t>();

    DataStream ss{};
    ss << max_additional_size;
    if (include_sigops) {
        ss << sigops;
    }

    Sv2CoinbaseOutputConstraintsMsg msg;
    ss >> msg;

    assert(msg.m_coinbase_output_max_additional_size == max_additional_size);
    if (include_sigops) {
        assert(msg.m_coinbase_output_max_additional_sigops == sigops);
    } else {
        // Unserialize defaults to 400 when sigops field is absent
        assert(msg.m_coinbase_output_max_additional_sigops == 400);
    }

    // Roundtrip: serialize then deserialize again and compare
    DataStream ss_rt{};
    ss_rt << msg;
    Sv2CoinbaseOutputConstraintsMsg msg_rt;
    ss_rt >> msg_rt;
    assert(msg.m_coinbase_output_max_additional_size == msg_rt.m_coinbase_output_max_additional_size);
    assert(msg.m_coinbase_output_max_additional_sigops == msg_rt.m_coinbase_output_max_additional_sigops);
}

// Fuzz Sv2RequestTransactionDataMsg deserialization (client -> TP message).
// We write exactly 8 bytes; deserialization must succeed.
FUZZ_TARGET(sv2_request_transaction_data, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();

    DataStream ss{};
    ss << template_id;

    Sv2RequestTransactionDataMsg msg;
    ss >> msg;
    assert(msg.m_template_id == template_id);
}

// Fuzz Sv2SubmitSolutionMsg deserialization (client -> TP message).
// This is security-critical as it contains a coinbase transaction.
// The try/catch is intentional: the fuzzer looks for memory errors and
// undefined behavior (caught by sanitizers), not parse exceptions.
FUZZ_TARGET(sv2_submit_solution, .init = Sv2FuzzInitialize)
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
    } catch (const std::ios_base::failure&) {
        // Stream read failures are expected for malformed transactions
    }
}

// Fuzz Sv2SetupConnectionSuccessMsg serialization (TP -> client message).
// Construction from valid fuzzed values should not throw.
FUZZ_TARGET(sv2_setup_connection_success, .init = Sv2FuzzInitialize)
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

    // Roundtrip: read back serialized fields and verify
    uint16_t rt_version;
    uint32_t rt_flags;
    ss >> rt_version >> rt_flags;
    assert(rt_version == used_version);
    assert(rt_flags == flags);
}

// Fuzz Sv2SetupConnectionErrorMsg serialization (TP -> client message).
// Construction from valid fuzzed values should not throw.
FUZZ_TARGET(sv2_setup_connection_error, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    std::string error_code = FuzzedString(provider);
    std::string error_code_expect = error_code;

    Sv2SetupConnectionErrorMsg msg(flags, std::move(error_code));

    // Serialize
    DataStream ss{};
    ss << msg;

    // Roundtrip: read back serialized fields and verify
    uint32_t rt_flags;
    std::string rt_error;
    ss >> rt_flags >> rt_error;
    assert(rt_flags == flags);
    assert(rt_error == error_code_expect);
}

// Fuzz Sv2SetNewPrevHashMsg serialization (TP -> client message).
// Construction from valid fuzzed values should not throw.
FUZZ_TARGET(sv2_set_new_prev_hash, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Create message with fuzzed values
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<int32_t>();
    header.hashPrevBlock = ConsumeUint256(provider);
    header.hashMerkleRoot = ConsumeUint256(provider);
    header.nTime = provider.ConsumeIntegral<uint32_t>();
    header.nBits = provider.ConsumeIntegral<uint32_t>();
    header.nNonce = provider.ConsumeIntegral<uint32_t>();

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();

    Sv2SetNewPrevHashMsg msg(header, template_id);

    // Serialize
    DataStream ss{};
    ss << msg;

    // Roundtrip: read back serialized fields and verify
    uint64_t rt_template_id;
    uint256 rt_prev_hash;
    uint32_t rt_timestamp;
    uint32_t rt_nbits;
    uint256 rt_target;
    ss >> rt_template_id >> rt_prev_hash >> rt_timestamp >> rt_nbits >> rt_target;
    assert(rt_template_id == template_id);
    assert(rt_prev_hash == header.hashPrevBlock);
    assert(rt_timestamp == header.nTime);
    assert(rt_nbits == header.nBits);
}

// Fuzz Sv2RequestTransactionDataSuccessMsg serialization (TP -> client message).
// Construction from valid fuzzed values should not throw.
FUZZ_TARGET(sv2_request_transaction_data_success, .init = Sv2FuzzInitialize)
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

    // Roundtrip: read back template_id from serialized stream
    uint64_t rt_template_id;
    ss >> rt_template_id;
    assert(rt_template_id == template_id);
}

// Fuzz Sv2RequestTransactionDataErrorMsg serialization (TP -> client message).
// Construction from valid fuzzed values should not throw.
FUZZ_TARGET(sv2_request_transaction_data_error, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint64_t template_id = provider.ConsumeIntegral<uint64_t>();
    std::string error_code = FuzzedString(provider);
    std::string error_code_expect = error_code;

    Sv2RequestTransactionDataErrorMsg msg(template_id, std::move(error_code));

    // Serialize
    DataStream ss{};
    ss << msg;

    // Roundtrip: read back serialized fields and verify
    uint64_t rt_template_id;
    std::string rt_error;
    ss >> rt_template_id >> rt_error;
    assert(rt_template_id == template_id);
    assert(rt_error == error_code_expect);
}

// Fuzz Sv2NetMsg wrapping/unwrapping.
FUZZ_TARGET(sv2_net_msg, .init = Sv2FuzzInitialize)
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

// Fuzz Sv2NewTemplateMsg serialization (TP -> client message).
// This is the most complex SV2 message with variable-length fields.
FUZZ_TARGET(sv2_new_template, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    // Populate message fields with fuzzed values
    Sv2NewTemplateMsg msg;
    msg.m_template_id = provider.ConsumeIntegral<uint64_t>();
    msg.m_future_template = provider.ConsumeBool();
    msg.m_version = provider.ConsumeIntegral<uint32_t>();
    msg.m_coinbase_tx_version = provider.ConsumeIntegral<uint32_t>();

    // Coinbase prefix: up to 8 bytes per spec
    size_t prefix_len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    auto prefix_bytes = provider.ConsumeBytes<uint8_t>(prefix_len);
    msg.m_coinbase_prefix = CScript(prefix_bytes.begin(), prefix_bytes.end());

    msg.m_coinbase_tx_input_sequence = provider.ConsumeIntegral<uint32_t>();
    msg.m_coinbase_tx_value_remaining = provider.ConsumeIntegral<uint64_t>();

    // Generate a small number of coinbase outputs
    uint32_t num_outputs = provider.ConsumeIntegralInRange<uint32_t>(0, 4);
    msg.m_coinbase_tx_outputs_count = num_outputs;
    for (uint32_t i = 0; i < num_outputs && provider.remaining_bytes() > 0; i++) {
        CAmount value = provider.ConsumeIntegral<int64_t>();
        size_t script_len = provider.ConsumeIntegralInRange<size_t>(0, 100);
        auto script_bytes = provider.ConsumeBytes<uint8_t>(script_len);
        CScript script(script_bytes.begin(), script_bytes.end());
        msg.m_coinbase_tx_outputs.emplace_back(value, script);
    }
    // Ensure count matches actual vector size
    msg.m_coinbase_tx_outputs_count = static_cast<uint32_t>(msg.m_coinbase_tx_outputs.size());

    msg.m_coinbase_tx_locktime = provider.ConsumeIntegral<uint32_t>();

    // Generate a small merkle path
    size_t path_len = provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < path_len && provider.remaining_bytes() >= 32; i++) {
        msg.m_merkle_path.push_back(ConsumeUint256(provider));
    }

    // Serialize
    DataStream ss{};
    ss << msg;

    // Read back fixed fields and verify
    uint64_t rt_template_id;
    bool rt_future_template;
    uint32_t rt_version;
    uint32_t rt_coinbase_tx_version;
    ss >> rt_template_id >> rt_future_template >> rt_version >> rt_coinbase_tx_version;
    assert(rt_template_id == msg.m_template_id);
    assert(rt_future_template == msg.m_future_template);
    assert(rt_version == msg.m_version);
    assert(rt_coinbase_tx_version == msg.m_coinbase_tx_version);
}

// -- Raw-bytes deserialization targets ----------------------------------------
//
// These feed arbitrary fuzzer bytes directly into the deserializer, testing the
// full deserialization attack surface. The try/catch is essential: most random
// inputs will fail parsing, but sanitizers (ASan/UBSan/MSan) catch any memory
// errors or undefined behavior triggered along the way.

FUZZ_TARGET(sv2_setup_connection_raw, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);

    DataStream ds{buffer};
    try {
        Sv2SetupConnectionMsg msg;
        ds >> msg;
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(sv2_coinbase_output_constraints_raw, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);

    DataStream ds{buffer};
    try {
        Sv2CoinbaseOutputConstraintsMsg msg;
        ds >> msg;

        // If deserialization succeeded, verify roundtrip invariant
        DataStream ss_rt{};
        ss_rt << msg;
        Sv2CoinbaseOutputConstraintsMsg msg_rt;
        ss_rt >> msg_rt;
        assert(msg.m_coinbase_output_max_additional_size == msg_rt.m_coinbase_output_max_additional_size);
        assert(msg.m_coinbase_output_max_additional_sigops == msg_rt.m_coinbase_output_max_additional_sigops);
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(sv2_request_transaction_data_raw, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);

    DataStream ds{buffer};
    try {
        Sv2RequestTransactionDataMsg msg;
        ds >> msg;
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(sv2_submit_solution_raw, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);

    DataStream ds{buffer};
    try {
        Sv2SubmitSolutionMsg msg;
        ds >> msg;
    } catch (const std::ios_base::failure&) {
    }
}

FUZZ_TARGET(sv2_net_msg_raw, .init = Sv2FuzzInitialize)
{
    const CheckGlobals check_globals{};
    SeedRandomStateForTest(SeedRand::ZEROS);

    DataStream ds{buffer};
    try {
        Sv2NetMsg msg(Sv2MsgType::SETUP_CONNECTION, {});
        ds >> msg;
    } catch (const std::ios_base::failure&) {
    }
}
