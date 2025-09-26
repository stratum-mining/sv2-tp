#include <boost/test/unit_test.hpp>
#include <interfaces/mining.h>
#include <interfaces/init.h>
#include <sv2/messages.h>
#include <test/sv2_mock_mining.h>
#include <test/sv2_test_setup.h>
#include <test/sv2_tp_tester.h>
#include <test/util/net.h>
#include <util/sock.h>
#include <util/strencodings.h>
// Synchronization primitives (Mutex/LOCK)
#include <sync.h>
// Additional headers for mocks and scripts
#include <script/script.h>

// Test harness and mocks
#include <future>
#include <memory>
#include <thread>

// TPTester handles IPC glue internally; no need to include IPC headers here

// For verbose debugging use:
// build/src/test/test_sv2 --run_test=sv2_template_provider_tests --log_level=all -- -debug=sv2 -loglevel=sv2:trace -printtoconsole=1 | grep -v disabled

BOOST_FIXTURE_TEST_SUITE(sv2_template_provider_tests, Sv2BasicTestingSetup)

BOOST_AUTO_TEST_CASE(client_tests)
{
    TPTester tester{};

    tester.handshake();

    // After the handshake the client must send a SetupConnection message to the
    // Template Provider.

    tester.handshake();
    BOOST_TEST_MESSAGE("Handshake done, send SetupConnectionMsg");

    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.receiveMessage(setup);
    // SetupConnection.Success is 6 bytes
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);

    // There should be no block templates before any client gave us their coinbase
    // output data size:
    BOOST_REQUIRE(tester.GetBlockTemplateCount() == 0);

    std::vector<uint8_t> coinbase_output_constraint_bytes{
        0x01, 0x00, 0x00, 0x00, // coinbase_output_max_additional_size
        0x00, 0x00              // coinbase_output_max_sigops
    };
    node::Sv2NetMsg msg{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_constraint_bytes)};
    tester.receiveMessage(msg);
    BOOST_TEST_MESSAGE("The reply should be NewTemplate and SetNewPrevHash");
    // Payload sizes for fixed-layout SV2 messages used in this test
    constexpr size_t SV2_SET_NEW_PREV_HASH_MESSAGE_SIZE = 8 + 32 + 4 + 4 + 32; // = 80
    constexpr size_t SV2_NEW_TEMPLATE_MESSAGE_SIZE =
        8 +                 // template_id
        1 +                 // future_template
        4 +                 // version
        4 +                 // coinbase_tx_version
    2 +                 // coinbase_prefix (CompactSize(1) + 1-byte OP_0)
        4 +                 // coinbase_tx_input_sequence
        8 +                 // coinbase_tx_value_remaining
        4 +                 // coinbase_tx_outputs_count (0)
        2 +                 // B0_64K length for outputs array (0)
        4 +                 // coinbase_tx_locktime
        1;                  // merkle_path count (CompactSize(0))

    // Two messages back-to-back: headers + payloads + 2 payload tags
    size_t bytes_first = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_first,
        2 * SV2_HEADER_ENCRYPTED_SIZE +
        SV2_NEW_TEMPLATE_MESSAGE_SIZE +
        SV2_SET_NEW_PREV_HASH_MESSAGE_SIZE +
        2 * Poly1305::TAGLEN);

    // There should now be one template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Move mock time
    // If the mempool doesn't change, no new template is generated.
    SetMockTime(GetMockTime() + std::chrono::seconds{10});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Simulate a fee increase by having the mock mining return a template with a tx
    std::vector<CTransactionRef> high_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(high_fee_txs);

    // Move mock time
    SetMockTime(GetMockTime() + std::chrono::seconds{tester.m_tp_options.fee_check_interval});

    // Briefly wait for block creation
    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Expect our peer to receive a NewTemplate message (prevhash unchanged)
    BOOST_TEST_MESSAGE("Receive NewTemplate (fee increase)");
    // One NewTemplate follows: header + payload + payload tag
    size_t bytes_fee_nt = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_fee_nt, SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MESSAGE_SIZE + Poly1305::TAGLEN);

    // Get the latest template id
    uint64_t template_id = 0;
    {
        LOCK(tester.m_tp->m_tp_mutex);
        for (auto& t : tester.m_tp->GetBlockTemplates()) {
            if (t.first > template_id) {
                template_id = t.first;
            }
        }
    }

    BOOST_REQUIRE_EQUAL(template_id, 2);

    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Have the peer send us RequestTransactionData
    // We should reply with RequestTransactionData.Success
    node::Sv2NetHeader req_tx_data_header{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, 8};
    DataStream ss;
    ss << template_id;
    std::vector<unsigned char> template_id_bytes;
    template_id_bytes.resize(8);
    ss >> MakeWritableByteSpan(template_id_bytes);

    msg = node::Sv2NetMsg{req_tx_data_header.m_msg_type, std::move(template_id_bytes)};
    tester.receiveMessage(msg);
    BOOST_TEST_MESSAGE("Receive RequestTransactionData.Success");
    // RequestTransactionData.Success on-wire size derived from constants and actual tx size
    constexpr size_t SV2_RTD_SUCCESS_PREFIX = 8 /*template_id*/ + 2 /*excess len*/ + 2 /*tx_count=1*/;
    constexpr size_t SV2_U24_LEN = 3; // u24 length per tx
    {
        // Serialize the same deterministic dummy transaction to get exact size
        const CTransactionRef tx_ref = MakeDummyTx();
        DataStream ss_tx{};
        ss_tx << TX_WITH_WITNESS(*tx_ref);
        const size_t tx_size = ss_tx.size();

        const size_t rtd_payload = SV2_RTD_SUCCESS_PREFIX + SV2_U24_LEN + tx_size;
        const size_t expected_rtd_onwire = SV2_HEADER_ENCRYPTED_SIZE + rtd_payload + Poly1305::TAGLEN;
        size_t bytes_req_success = tester.PeerReceiveBytes();
        BOOST_REQUIRE_EQUAL(bytes_req_success, expected_rtd_onwire);
    }
    // Simulate another fee increase (RBF-like) with a different tx
    std::vector<CTransactionRef> higher_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(higher_fee_txs);

    // Move mock time
    SetMockTime(GetMockTime() + std::chrono::seconds{tester.m_tp_options.fee_check_interval});

    // Briefly wait for the timer in ThreadSv2Handler and block creation
    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Wait a bit more for macOS native CI
    UninterruptibleSleep(std::chrono::milliseconds{1000});

    // Expect our peer to receive a NewTemplate message
    size_t bytes_second_nt = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_second_nt, SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MESSAGE_SIZE + Poly1305::TAGLEN);

    // Check that there's a new template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 3);

    // Have the peer send us RequestTransactionData for the old template
    // We should reply with RequestTransactionData.Success, and the original
    // (replaced) transaction
    tester.receiveMessage(msg);
    // Old template RequestTransactionData.Success again
    {
        const CTransactionRef tx_ref = MakeDummyTx();
        DataStream ss_tx{};
        ss_tx << TX_WITH_WITNESS(*tx_ref);
        const size_t tx_size = ss_tx.size();
        const size_t rtd_payload = SV2_RTD_SUCCESS_PREFIX + SV2_U24_LEN + tx_size;
        const size_t expected_rtd_onwire = SV2_HEADER_ENCRYPTED_SIZE + rtd_payload + Poly1305::TAGLEN;
        size_t bytes_req_success2 = tester.PeerReceiveBytes();
        BOOST_REQUIRE_EQUAL(bytes_req_success2, expected_rtd_onwire);
    }

    BOOST_TEST_MESSAGE("Create a new block (new tip)");
    tester.m_mining_control->TriggerNewTip();

    UninterruptibleSleep(std::chrono::milliseconds{200});

    // We should send out another NewTemplate and SetNewPrevHash (two messages)
    size_t bytes_tip_pair = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_tip_pair,
        2 * SV2_HEADER_ENCRYPTED_SIZE +
        SV2_NEW_TEMPLATE_MESSAGE_SIZE +
        SV2_SET_NEW_PREV_HASH_MESSAGE_SIZE +
        2 * Poly1305::TAGLEN);
    // The SetNewPrevHash message is redundant
    // TODO: don't send it?
    // Background: in the future we want to send an empty or optimistic template
    //             before a block is found, so ASIC's can preload it. We would
    //             then immedidately send a SetNewPrevHash message when there's
    //             a new block, and construct a better template _after_ that.

    // Templates are briefly preserved
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 4);

    // Do not provide transactions for stale templates
    // TODO

    // But do allow SubmitSolution
    // TODO

    // Until after some time
    SetMockTime(GetMockTime() + std::chrono::seconds{15});
    UninterruptibleSleep(std::chrono::milliseconds{1100});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Interrupt waitNext()
    tester.m_mining_control->Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()
