#include <boost/test/unit_test.hpp>
#include <sv2/messages.h>
#include <test/sv2_connman_tester.h>
#include <test/sv2_test_setup.h>

BOOST_FIXTURE_TEST_SUITE(sv2_connman_tests, Sv2BasicTestingSetup)

BOOST_AUTO_TEST_CASE(client_tests)
{
    ConnTester tester{};

    BOOST_REQUIRE(!tester.IsConnected());
    tester.handshake();
    BOOST_REQUIRE(!tester.IsFullyConnected());

    // After the handshake the remote peer must send a SetupConnection message to the
    // Template Provider.

    // An empty SetupConnection message should cause disconnection
    node::Sv2NetMsg sv2_msg{node::Sv2MsgType::SETUP_CONNECTION, {}};
    tester.RemoteToLocalMsg(sv2_msg);
    // Consume potential disconnect bytes via tolerant reader (expecting closure: helper would timeout if bytes keep coming)
    // Fall back to legacy single read; if bytes present they should form a complete frame immediately.
    auto first = tester.LocalToRemoteBytes();
    BOOST_REQUIRE_EQUAL(first, 0);

    BOOST_REQUIRE(!tester.IsConnected());

    BOOST_TEST_MESSAGE("Reconnect after empty message");

    // Reconnect
    tester.handshake();
    BOOST_TEST_MESSAGE("Handshake done, send SetupConnectionMsg");

    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.RemoteToLocalMsg(setup);
    // SetupConnection.Success is 6 bytes
    auto [response, response_bytes]{tester.LocalToRemoteMsg()};
    BOOST_REQUIRE_EQUAL(response_bytes, SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
    BOOST_REQUIRE(response.m_msg_type == node::Sv2MsgType::SETUP_CONNECTION_SUCCESS);
    DataStream response_stream{response.m_msg};
    uint16_t used_version;
    uint32_t flags;
    response_stream >> used_version >> flags;
    BOOST_REQUIRE_EQUAL(used_version, 2);
    BOOST_REQUIRE_EQUAL(flags, 0);
    BOOST_REQUIRE(tester.IsFullyConnected());

    std::vector<uint8_t> coinbase_output_max_additional_size_bytes{
        0x01, 0x00, 0x00, 0x00
    };
    node::Sv2NetMsg msg{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_max_additional_size_bytes)};
    // No reply expected, not yet implemented
    tester.RemoteToLocalMsg(msg);
}

BOOST_AUTO_TEST_CASE(submit_solution_before_setup_connection_forwarded)
{
    Sv2LogCapture logs;
    ConnTester tester{};

    tester.handshake();
    node::Sv2NetMsg solution{TestSubmitSolutionMsg()};
    tester.RemoteToLocalMsg(solution);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_submit_solution_count, 1));
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_REQUIRE(logs.WaitFor("Received SubmitSolution before SetupConnection and CoinbaseOutputConstraints (setup_connection=0, coinbase_output_constraints=0)"));
}

// Forward SubmitSolution even when the client skipped CoinbaseOutputConstraints.
BOOST_AUTO_TEST_CASE(submit_solution_forwarded)
{
    Sv2LogCapture logs;
    ConnTester tester{};

    tester.handshake();
    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.RemoteToLocalMsg(setup);
    BOOST_REQUIRE_EQUAL(tester.LocalToRemoteBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
    BOOST_REQUIRE(tester.IsFullyConnected());

    BOOST_TEST_MESSAGE("SubmitSolution without CoinbaseOutputConstraints is still forwarded");
    node::Sv2NetMsg premature_solution{TestSubmitSolutionMsg()};
    tester.RemoteToLocalMsg(premature_solution);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_submit_solution_count, 1));
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_REQUIRE(logs.WaitFor("Received SubmitSolution before SetupConnection and CoinbaseOutputConstraints (setup_connection=1, coinbase_output_constraints=0)"));

    std::vector<uint8_t> coinbase_output_max_additional_size_bytes{
        0x01, 0x00, 0x00, 0x00
    };
    node::Sv2NetMsg constraints{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_max_additional_size_bytes)};
    tester.RemoteToLocalMsg(constraints);

    node::Sv2NetMsg solution{TestSubmitSolutionMsg()};
    tester.RemoteToLocalMsg(solution);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_submit_solution_count, 2));
    BOOST_REQUIRE(tester.IsConnected());
}

// A reconnecting client may request transactions for a previous template before
// submitting its solution. Missing constraints must not disconnect it first.
BOOST_AUTO_TEST_CASE(submit_solution_after_premature_request_transaction_data)
{
    Sv2LogCapture logs;
    ConnTester tester{};

    tester.handshake();
    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.RemoteToLocalMsg(setup);
    BOOST_REQUIRE_EQUAL(tester.LocalToRemoteBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
    BOOST_REQUIRE(tester.GetReceivedMessage().m_msg_type == node::Sv2MsgType::SETUP_CONNECTION_SUCCESS);

    std::vector<uint8_t> template_id_bytes{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    node::Sv2NetMsg request{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, std::move(template_id_bytes)};
    tester.RemoteToLocalMsg(request);
    node::Sv2NetMsg solution{TestSubmitSolutionMsg()};
    tester.RemoteToLocalMsg(solution);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_submit_solution_count, 1));
    BOOST_REQUIRE(tester.LocalToRemoteBytes() > 0);
    const auto reply{tester.GetReceivedMessage()};
    const node::Sv2NetMsg expected{node::Sv2RequestTransactionDataErrorMsg{2, "setup-incomplete"}};
    BOOST_REQUIRE(reply.m_msg_type == expected.m_msg_type);
    BOOST_REQUIRE(reply.m_msg == expected.m_msg);
    BOOST_REQUIRE_EQUAL(tester.m_request_transaction_data_count.load(), 0);
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_REQUIRE(logs.WaitFor("Received RequestTransactionData before SetupConnection and CoinbaseOutputConstraints (setup_connection=1, coinbase_output_constraints=0)"));

    // Completing setup lets the client retry on the same connection.
    std::vector<uint8_t> constraints_bytes{0x01, 0x00, 0x00, 0x00};
    node::Sv2NetMsg constraints{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(constraints_bytes)};
    tester.RemoteToLocalMsg(constraints);
    node::Sv2NetMsg retry{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    tester.RemoteToLocalMsg(retry);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_request_transaction_data_count, 1));
    BOOST_REQUIRE(tester.IsConnected());
}

BOOST_AUTO_TEST_CASE(request_transaction_data_before_setup_connection_error)
{
    Sv2LogCapture logs;
    ConnTester tester{};

    tester.handshake();
    std::vector<uint8_t> template_id_bytes{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    node::Sv2NetMsg request{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, std::move(template_id_bytes)};
    tester.RemoteToLocalMsg(request);
    BOOST_REQUIRE(tester.LocalToRemoteBytes() > 0);
    const auto reply{tester.GetReceivedMessage()};
    const node::Sv2NetMsg expected{node::Sv2RequestTransactionDataErrorMsg{2, "setup-incomplete"}};
    BOOST_REQUIRE(reply.m_msg_type == expected.m_msg_type);
    BOOST_REQUIRE(reply.m_msg == expected.m_msg);
    BOOST_REQUIRE_EQUAL(tester.m_request_transaction_data_count.load(), 0);
    BOOST_REQUIRE(tester.IsConnected());
    BOOST_REQUIRE(logs.WaitFor("Received RequestTransactionData before SetupConnection and CoinbaseOutputConstraints (setup_connection=0, coinbase_output_constraints=0)"));

    node::Sv2NetMsg solution{TestSubmitSolutionMsg()};
    tester.RemoteToLocalMsg(solution);
    BOOST_REQUIRE(tester.WaitForCount(tester.m_submit_solution_count, 1));
    BOOST_REQUIRE(tester.IsConnected());
}

BOOST_AUTO_TEST_CASE(setup_connection_validation)
{
    ConnTester tester{};
    constexpr uint32_t OPTIONAL_FLAG{uint32_t{1} << 16};

    const auto check_error = [&tester](uint8_t protocol, uint16_t min_version,
                                       uint16_t max_version, uint32_t flags,
                                       uint32_t expected_flags, const std::string& expected_error) {
        tester.handshake();
        node::Sv2NetMsg setup{tester.SetupConnectionMsg(protocol, min_version, max_version, flags)};
        tester.RemoteToLocalMsg(setup);

        auto [response, _response_bytes]{tester.LocalToRemoteMsg()};
        BOOST_REQUIRE(response.m_msg_type == node::Sv2MsgType::SETUP_CONNECTION_ERROR);
        DataStream response_stream{response.m_msg};
        uint32_t response_flags;
        std::string error_code;
        response_stream >> response_flags >> error_code;
        BOOST_REQUIRE_EQUAL(response_flags, expected_flags);
        BOOST_REQUIRE_EQUAL(error_code, expected_error);
        BOOST_REQUIRE(!tester.IsFullyConnected());
    };

    check_error(/*protocol=*/3, /*min_version=*/2, /*max_version=*/2, /*flags=*/1,
                /*expected_flags=*/1, "unsupported-protocol");
    check_error(node::TEMPLATE_DISTRIBUTION_PROTOCOL, /*min_version=*/3, /*max_version=*/2, /*flags=*/2,
                /*expected_flags=*/2, "protocol-version-mismatch");
    check_error(node::TEMPLATE_DISTRIBUTION_PROTOCOL, /*min_version=*/2, /*max_version=*/2, /*flags=*/OPTIONAL_FLAG | 1,
                /*expected_flags=*/1, "unsupported-feature-flags");
}

BOOST_AUTO_TEST_CASE(setup_connection_optional_flags)
{
    ConnTester tester{};
    constexpr uint32_t OPTIONAL_FLAG{uint32_t{1} << 16};

    tester.handshake();
    node::Sv2NetMsg setup{tester.SetupConnectionMsg(node::TEMPLATE_DISTRIBUTION_PROTOCOL,
                                                    /*min_version=*/2, /*max_version=*/2,
                                                    /*flags=*/OPTIONAL_FLAG)};
    tester.RemoteToLocalMsg(setup);

    auto [response, _response_bytes]{tester.LocalToRemoteMsg()};
    BOOST_REQUIRE(response.m_msg_type == node::Sv2MsgType::SETUP_CONNECTION_SUCCESS);
    DataStream response_stream{response.m_msg};
    uint16_t used_version;
    uint32_t flags;
    response_stream >> used_version >> flags;
    BOOST_REQUIRE_EQUAL(used_version, 2);
    BOOST_REQUIRE_EQUAL(flags, 0);
    BOOST_REQUIRE(tester.IsFullyConnected());
}

// Only CoinbaseOutputConstraints that pass validation make a client ready for
// templates. Otherwise the template provider could start a handler thread for
// a client that is about to be disconnected.
BOOST_AUTO_TEST_CASE(coinbase_output_constraints_set_after_validation)
{
    ConnTester tester{};
    Sv2Client accepted{/*id=*/100, /*transport=*/nullptr};
    Sv2Client rejected{/*id=*/101, /*transport=*/nullptr};
    for (Sv2Client* client : {&accepted, &rejected}) {
        LOCK(client->cs_status);
        client->m_setup_connection_confirmed = true;
    }

    // 4'000'001 bytes can never fit in a block.
    node::Sv2NetMsg too_large{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, {0x01, 0x09, 0x3d, 0x00, 0x00, 0x00}};
    tester.m_connman->ProcessSv2Message(too_large, rejected);
    {
        LOCK(rejected.cs_status);
        BOOST_CHECK(rejected.m_disconnect_flag);
        BOOST_CHECK(!rejected.m_coinbase_output_constraints_recv);
    }
    BOOST_CHECK_EQUAL(rejected.m_coinbase_constraints_generation.load(), 0U);

    node::Sv2NetMsg constraints{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, {0x01, 0x00, 0x00, 0x00, 0x00, 0x00}};
    tester.m_connman->ProcessSv2Message(constraints, accepted);
    {
        LOCK(accepted.cs_status);
        BOOST_CHECK(!accepted.m_disconnect_flag);
        BOOST_CHECK(accepted.m_coinbase_output_constraints_recv);
        BOOST_CHECK_EQUAL(accepted.m_coinbase_tx_outputs_size, 1U);
    }
    BOOST_CHECK_EQUAL(accepted.m_coinbase_constraints_generation.load(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
