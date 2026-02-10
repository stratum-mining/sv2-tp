#include <consensus/amount.h>
#include <boost/test/unit_test.hpp>
#include <sv2/messages.h>
#include <util/strencodings.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <script/script.h>

BOOST_AUTO_TEST_SUITE(sv2_messages_tests)

BOOST_AUTO_TEST_CASE(Sv2SetupConnection_test)
{
    uint8_t input[]{
        0x02,                                                 // protocol
        0x02, 0x00,                                           // min_version
        0x02, 0x00,                                           // max_version
        0x01, 0x00, 0x00, 0x00,                               // flags
        0x07, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30,       // endpoint_host
        0x61, 0x21,                                           // endpoint_port
        0x07, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x69, 0x6e,       // vendor
        0x08, 0x53, 0x39, 0x69, 0x20, 0x31, 0x33, 0x2e, 0x35, // hardware_version
        0x1c, 0x62, 0x72, 0x61, 0x69, 0x69, 0x6e, 0x73, 0x2d, 0x6f, 0x73, 0x2d, 0x32, 0x30,
        0x31, 0x38, 0x2d, 0x30, 0x39, 0x2d, 0x32, 0x32, 0x2d, 0x31, 0x2d, 0x68, 0x61, 0x73,
        0x68, // firmware
        0x10, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
        0x75, 0x69, 0x64, // device_id
    };
    BOOST_CHECK_EQUAL(sizeof(input), 82);

    DataStream ss(input);
    BOOST_CHECK_EQUAL(ss.size(), sizeof(input));

    node::Sv2SetupConnectionMsg setup_conn;
    ss >> setup_conn;

    BOOST_CHECK_EQUAL(setup_conn.m_protocol, 2);
    BOOST_CHECK_EQUAL(setup_conn.m_min_version, 2);
    BOOST_CHECK_EQUAL(setup_conn.m_max_version, 2);
    BOOST_CHECK_EQUAL(setup_conn.m_flags, 1);
    BOOST_CHECK_EQUAL(setup_conn.m_endpoint_host, "0.0.0.0");
    BOOST_CHECK_EQUAL(setup_conn.m_endpoint_port, 8545);
    BOOST_CHECK_EQUAL(setup_conn.m_vendor, "Bitmain");
    BOOST_CHECK_EQUAL(setup_conn.m_hardware_version, "S9i 13.5");
    BOOST_CHECK_EQUAL(setup_conn.m_firmware, "braiins-os-2018-09-22-1-hash");
    BOOST_CHECK_EQUAL(setup_conn.m_device_id, "some-device-uuid");
}

BOOST_AUTO_TEST_CASE(Sv2NetHeader_SetupConnection_test)
{
    uint8_t input[]{
        0x00, 0x00,       // extension type
        0x00,             // msg type (SetupConnection)
        0x52, 0x00, 0x00, // msg length
    };

    DataStream ss(input);
    node::Sv2NetHeader sv2_header;
    ss >> sv2_header;

    BOOST_CHECK(sv2_header.m_msg_type == node::Sv2MsgType::SETUP_CONNECTION);
    BOOST_CHECK_EQUAL(sv2_header.m_msg_len, 82);
}

BOOST_AUTO_TEST_CASE(Sv2SetupConnectionSuccess_test)
{
    // 0200 - used_version
    // 03000000 - flags
    std::string expected{"020003000000"};
    node::Sv2SetupConnectionSuccessMsg setup_conn_success{2, 3};

    DataStream ss{};
    ss << setup_conn_success;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2NetMsg_SetupConnectionSuccess_test)
{
    // 0200     - used_version
    // 03000000 - flags
    std::string expected{"01020003000000"};
    node::Sv2NetMsg sv2_net_msg{node::Sv2SetupConnectionSuccessMsg{2, 3}};

    DataStream ss{};
    ss << sv2_net_msg;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2SetupConnectionError_test)
{
    // 00 00 00 00     - flags
    // 19 - error_code length
    // 70726f746f636f6c2d76657273696f6e2d6d69736d61746368 - error_code
    std::string expected{"000000001970726f746f636f6c2d76657273696f6e2d6d69736d61746368"};
    node::Sv2SetupConnectionErrorMsg setup_conn_err{0, std::string{"protocol-version-mismatch"}};

    DataStream ss{};
    ss << setup_conn_err;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}


BOOST_AUTO_TEST_CASE(Sv2NewTemplate_test)
{
    // NewTemplate
    // https://github.com/stratum-mining/sv2-spec/blob/main/07-Template-Distribution-Protocol.md#72-newtemplate-server---client
    //
    // U64              0100000000000000    template_id
    // BOOL             00                  future_template
    // U32              00000030            version
    // U32              02000000            coinbase tx version
    // B0_255           04                  coinbase_prefix len
    //                  03012100            coinbase prefix
    // U256             0000000000000000000000000000000000000000000000000000000000000000 - witness
    // U32              ffffffff            coinbase tx input sequence
    // U64              0040075af0750700    coinbase tx value remaining
    // U32              01000000            coinbase tx outputs count
    // B0_64K           0c                  coinbase_tx_outputs (concatenated, total bytes)
    //                  000100000000000000  amount
    //                  036a012a            len(script) + script
    // U32              dbc80d00            coinbase lock time (height 903,387)
    // SEQ0_255[U256]   01                  merkle path length
    //                  1a6240823de4c8d6aaf826851bdf2b0e8d5acf7c31e8578cff4c394b5a32bd4e - merkle path
    std::string expected{"010000000000000000000000300200000004030121000000000000000000000000000000000000000000000000000000000000000000ffffffff0040075af0750700010000000c000100000000000000036a012adbc80d00011a6240823de4c8d6aaf826851bdf2b0e8d5acf7c31e8578cff4c394b5a32bd4e"};

    node::Sv2NewTemplateMsg new_template;
    new_template.m_template_id = 1;
    new_template.m_future_template = false;
    new_template.m_version = 805306368;
    new_template.m_coinbase_tx_version = 2;

    std::vector<uint8_t> coinbase_prefix{0x03, 0x01, 0x21, 0x00};
    CScript prefix(coinbase_prefix.begin(), coinbase_prefix.end());
    new_template.m_coinbase_prefix = prefix;

    new_template.m_coinbase_witness = uint256(0);

    new_template.m_coinbase_tx_input_sequence = 4294967295;
    new_template.m_coinbase_tx_value_remaining = MAX_MONEY;

    // Create fake witness commitment
    new_template.m_coinbase_tx_outputs_count = 1;
    std::vector<CTxOut> coinbase_tx_ouputs{CTxOut(1, CScript() << OP_RETURN << 42)};
    new_template.m_coinbase_tx_outputs = coinbase_tx_ouputs;

    new_template.m_coinbase_tx_locktime = 903387;

    std::vector<uint256> merkle_path;
    CMutableTransaction mtx_tx;
    CTransaction tx{mtx_tx};
    merkle_path.push_back(tx.GetHash().ToUint256());
    new_template.m_merkle_path = merkle_path;

    DataStream ss{};
    ss << new_template;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2NewTemplate_MultipleOutputs_test)
{
    // NewTemplate with realistic coinbase: 1 dummy anyone-can-spend output + 3 OP_RETURN outputs
    // Tests that only OP_RETURN outputs are serialized (dummy output filtered out)
    //
    // U64              0100000000000000    template_id
    // BOOL             00                  future_template
    // U32              00000030            version
    // U32              02000000            coinbase tx version
    // B0_255           04                  coinbase_prefix len
    //                  03012100            coinbase prefix
    // U256             0000000000000000000000000000000000000000000000000000000000000000 - witness
    // U32              ffffffff            coinbase tx input sequence
    // U64              0040075af0750700    coinbase tx value remaining
    // U32              03000000            coinbase tx outputs count (3 OP_RETURN outputs, dummy filtered)
    // B0_64K           2100                coinbase_tx_outputs (33 bytes total)
    //                  6400000000000000    output 1: 100 sats
    //                  026a51              output 1: script (OP_RETURN OP_1)
    //                  c800000000000000    output 2: 200 sats
    //                  026a52              output 2: script (OP_RETURN OP_2)
    //                  2c01000000000000    output 3: 300 sats
    //                  026a53              output 3: script (OP_RETURN OP_3)
    // U32              dbc80d00            coinbase lock time (height 903,387)
    // SEQ0_255[U256]   01                  merkle path length
    //                  1a6240823de4c8d6aaf826851bdf2b0e8d5acf7c31e8578cff4c394b5a32bd4e - merkle path
    std::string expected{"010000000000000000000000300200000004030121000000000000000000000000000000000000000000000000000000000000000000ffffffff0040075af07507000300000021006400000000000000026a51c800000000000000026a522c01000000000000026a53dbc80d00011a6240823de4c8d6aaf826851bdf2b0e8d5acf7c31e8578cff4c394b5a32bd4e"};

    // Create realistic coinbase transaction with dummy anyone-can-spend output
    CMutableTransaction coinbase_tx;
    coinbase_tx.version = 2;
    coinbase_tx.vin.resize(1);
    coinbase_tx.vin[0].prevout.SetNull();
    std::vector<uint8_t> coinbase_prefix_bytes{0x03, 0x01, 0x21, 0x00};
    coinbase_tx.vin[0].scriptSig = CScript(coinbase_prefix_bytes.begin(), coinbase_prefix_bytes.end());
    coinbase_tx.vin[0].nSequence = 4294967295;

    coinbase_tx.vout.resize(4);
    // Output 0: Dummy anyone-can-spend output with full reward (will be filtered out by sv2-tp)
    coinbase_tx.vout[0].nValue = MAX_MONEY;
    coinbase_tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Outputs 1-3: OP_RETURN outputs (will be included in NewTemplate message)
    coinbase_tx.vout[1] = CTxOut(100, CScript() << OP_RETURN << 1);
    coinbase_tx.vout[2] = CTxOut(200, CScript() << OP_RETURN << 2);
    coinbase_tx.vout[3] = CTxOut(300, CScript() << OP_RETURN << 3);

    coinbase_tx.nLockTime = 903387;

    CBlockHeader header;
    header.nVersion = 805306368;
    header.hashPrevBlock.SetNull();
    header.nTime = 0;
    header.nBits = 0;
    header.nNonce = 0;

    std::vector<uint256> merkle_path;
    CMutableTransaction mtx_tx;
    CTransaction tx{mtx_tx};
    merkle_path.push_back(tx.GetHash().ToUint256());

    // Use constructor which filters outputs to only OP_RETURN
    node::Sv2NewTemplateMsg new_template{header, MakeTransactionRef(coinbase_tx), merkle_path, 1, false};

    DataStream ss{};
    ss << new_template;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2NetHeader_NewTemplate_test)
{
    // 0000 - extension type
    // 71 - msg type (NewTemplate)
    // 000000 - msg length
    std::string expected{"000071000000"};
    node::Sv2NetHeader sv2_header{node::Sv2MsgType::NEW_TEMPLATE, 0};

    DataStream ss{};
    ss << sv2_header;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}


BOOST_AUTO_TEST_CASE(Sv2SetNewPrevHash_test)
{
    // 0200000000000000 - template_id
    // e59a2ef8d4826b89fe637f3b 5322c0f167fd2d3dc88ec568a7c2c8ffd8eb8873 - prev hash
    // 973c0e63 - header timestamp
    // ffff7f03 - nbits
    // ffff7f0000000000000000000000000000000000000000000000000000000000 - target
    std::string expected{"0200000000000000e59a2ef8d4826b89fe637f3b5322c0f167fd2d3dc88ec568a7c2c8ffd8eb8873973c0e63ffff7f03ffff7f0000000000000000000000000000000000000000000000000000000000"};

    std::vector<uint8_t> prev_hash_input{
        0xe5, 0x9a, 0x2e, 0xf8, 0xd4, 0x82, 0x6b, 0x89, 0xfe, 0x63, 0x7f, 0x3b,
        0x53, 0x22, 0xc0, 0xf1, 0x67, 0xfd, 0x2d, 0x3d, 0xc8, 0x8e, 0xc5, 0x68,
        0xa7, 0xc2, 0xc8, 0xff, 0xd8, 0xeb, 0x88, 0x73};
    uint256 prev_hash = uint256(prev_hash_input);

    CBlockHeader header;
    header.hashPrevBlock = prev_hash;
    header.nTime = 1661877399;
    header.nBits = 58720255;

    node::Sv2SetNewPrevHashMsg new_prev_hash{header, 2};

    DataStream ss{};
    ss << new_prev_hash;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2NetHeader_SetNewPrevHash_test)
{
    // 0000 - extension type
    // 72 - msg type (SetNewPrevHash)
    // 000000 - msg length
    std::string expected{"000072000000"};
    node::Sv2NetHeader sv2_header{node::Sv2MsgType::SET_NEW_PREV_HASH, 0};

    DataStream ss{};
    ss << sv2_header;

    BOOST_CHECK_EQUAL(HexStr(ss), expected);
}

BOOST_AUTO_TEST_CASE(Sv2SubmitSolution_test)
{
    uint8_t input[]{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // template_id
        0x02, 0x00, 0x00, 0x00,                           // version
        0x97, 0x3c, 0x0e, 0x63,                           // header_timestamp
        0xff, 0xff, 0x7f, 0x03,                           // header_nonce
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
    DataStream ss(input);

    node::Sv2SubmitSolutionMsg submit_solution;
    ss >> submit_solution;

    // BOOST_CHECK_EQUAL(submit_solution.m_template_id, 2);
    // BOOST_CHECK_EQUAL(submit_solution.m_version, 2);
    // BOOST_CHECK_EQUAL(submit_solution.m_header_timestamp, 1661877399);
    // BOOST_CHECK_EQUAL(submit_solution.m_header_nonce, 58720255);
}
BOOST_AUTO_TEST_SUITE_END()
