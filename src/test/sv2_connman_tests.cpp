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

BOOST_AUTO_TEST_SUITE_END()
