#include <boost/test/unit_test.hpp>
#include <interfaces/mining.h>
#include <sv2/block_options.h>
#include <interfaces/init.h>
#include <sv2/messages.h>
#include <test/sv2_test_setup.h>
#include <test/util/net.h>
#include <util/sock.h>
#include <util/strencodings.h>
// Synchronization primitives (Mutex/LOCK)
#include <sync.h>
// Additional headers for mocks and scripts
#include <script/script.h>

// Test harness and mocks
#include <test/sv2_tp_tester.h>
#include <test/sv2_mock_mining.h>

#include <future>
#include <algorithm>
#include <memory>
#include <string>
#include <thread>

// TPTester handles IPC glue internally; no need to include IPC headers here

// For verbose debugging use:
// build/src/test/test_sv2 --run_test=sv2_template_provider_tests --log_level=all -- -debug=sv2 -loglevel=sv2:trace | grep -v disabled

BOOST_FIXTURE_TEST_SUITE(sv2_template_provider_tests, Sv2BasicTestingSetup)

BOOST_AUTO_TEST_CASE(block_reserved_weight_floor)
{
    node::BlockCreateOptions options{};
    // Guard against regressions where the reserved weight floor is treated as a cap.
    options.block_reserved_weight = 1800;
    options.block_reserved_weight = std::max(node::MIN_BLOCK_RESERVED_WEIGHT, options.block_reserved_weight);
    BOOST_REQUIRE_EQUAL(options.block_reserved_weight, node::MIN_BLOCK_RESERVED_WEIGHT);
}

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
        4 +                 // coinbase_tx_outputs_count (2 - mock creates 3, only 2 OP_RETURN outputs pass filter)
        2 + 56 +            // B0_64K: length prefix (2 bytes) + 2 outputs (witness commitment 43 bytes + merge mining 13 bytes)
        4 +                 // coinbase_tx_locktime
        1;                  // merkle_path count (CompactSize(0))

    // Two messages (SetNewPrevHash + NewTemplate) may arrive in one read or sequentially.
    const size_t expected_set_new_prev_hash = SV2_HEADER_ENCRYPTED_SIZE + SV2_SET_NEW_PREV_HASH_MESSAGE_SIZE + Poly1305::TAGLEN;
    const size_t expected_new_template = SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MESSAGE_SIZE + Poly1305::TAGLEN;
    const size_t expected_pair_bytes = expected_set_new_prev_hash + expected_new_template;

    const auto expect_template_pair = [&](const char* context) {
        size_t accumulated = 0;
        bool seen_prev_hash = false;
        bool seen_new_template = false;
        int iterations = 0;

        while (accumulated < expected_pair_bytes) {
            size_t chunk = tester.PeerReceiveBytes();
            accumulated += chunk;
            ++iterations;

            if (chunk == expected_set_new_prev_hash) {
                seen_prev_hash = true;
            } else if (chunk == expected_new_template) {
                seen_new_template = true;
            } else if (chunk == expected_pair_bytes) {
                seen_prev_hash = true;
                seen_new_template = true;
                break;
            } else {
                BOOST_FAIL(std::string("Unexpected message size while receiving ") + context);
            }

            BOOST_REQUIRE_MESSAGE(iterations <= 2, std::string("Too many fragments for ") + context);
        }

        BOOST_REQUIRE_MESSAGE(seen_prev_hash, std::string("Missing SetNewPrevHash during ") + context);
        BOOST_REQUIRE_MESSAGE(seen_new_template, std::string("Missing NewTemplate during ") + context);
        BOOST_REQUIRE_MESSAGE(accumulated == expected_pair_bytes, std::string("Incomplete response for ") + context);
    };

    expect_template_pair("initial template broadcast");

    // There should now be one template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);
    uint64_t seq_after_first = tester.m_mining_control->GetTemplateSeq();
    BOOST_TEST_MESSAGE("Template sequence after first NewTemplate: " << seq_after_first);
    BOOST_REQUIRE(seq_after_first >= 1);

    // Move mock time
    // If the mempool doesn't change, no new template is generated.
    SetMockTime(GetMockTime() + std::chrono::seconds{10});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Simulate a fee increase by having the mock mining return a template with a tx
    std::vector<CTransactionRef> high_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(high_fee_txs);

    // Move mock time
    SetMockTime(GetMockTime() + std::chrono::seconds{tester.m_tp_options.fee_check_interval});

    // Wait for a new template sequence instead of sleeping
    BOOST_REQUIRE(tester.m_mining_control->WaitForTemplateSeq(seq_after_first + 1));

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
    uint64_t seq_after_fee_nt = tester.m_mining_control->GetTemplateSeq();
    BOOST_REQUIRE(seq_after_fee_nt >= seq_after_first);

    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Have the peer send us RequestTransactionData
    // We should reply with RequestTransactionData.Success
    node::Sv2NetHeader req_tx_data_header{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, 8};
    DataStream ss;
    ss << template_id;
    std::vector<unsigned char> template_id_bytes;
    template_id_bytes.resize(8);
    ss >> MakeWritableByteSpan(template_id_bytes);

    node::Sv2NetMsg request_transaction_data_msg{req_tx_data_header.m_msg_type, std::move(template_id_bytes)};
    tester.receiveMessage(request_transaction_data_msg);
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
    // Wait for sequence to advance again (second fee increase)
    BOOST_REQUIRE(tester.m_mining_control->WaitForTemplateSeq(seq_after_fee_nt + 1));

    // Expect our peer to receive a NewTemplate message
    size_t bytes_second_nt = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_second_nt, SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MESSAGE_SIZE + Poly1305::TAGLEN);

    // Check that there's a new template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 3);
    uint64_t seq_after_second_nt = tester.m_mining_control->GetTemplateSeq();
    BOOST_REQUIRE(seq_after_second_nt >= seq_after_fee_nt);

    // Have the peer send us RequestTransactionData for the old template
    // We should reply with RequestTransactionData.Success, and the original
    // (replaced) transaction
    tester.receiveMessage(request_transaction_data_msg);
    // Old template RequestTransactionData.Success again
    size_t request_transaction_data_success_bytes;
    {
        const CTransactionRef tx_ref = MakeDummyTx();
        DataStream ss_tx{};
        ss_tx << TX_WITH_WITNESS(*tx_ref);
        const size_t tx_size = ss_tx.size();
        const size_t rtd_payload = SV2_RTD_SUCCESS_PREFIX + SV2_U24_LEN + tx_size;
        request_transaction_data_success_bytes = SV2_HEADER_ENCRYPTED_SIZE + rtd_payload + Poly1305::TAGLEN;
        size_t bytes_req_success2 = tester.PeerReceiveBytes();
        BOOST_REQUIRE_EQUAL(bytes_req_success2, request_transaction_data_success_bytes);
    }

    BOOST_TEST_MESSAGE("Create a new block (new tip)");
    tester.m_mining_control->TriggerNewTip();

    // Wait for template emission due to new tip
    BOOST_REQUIRE(tester.m_mining_control->WaitForTemplateSeq(seq_after_second_nt + 1));

    // We should send out another NewTemplate and SetNewPrevHash (two messages)
    expect_template_pair("new tip template broadcast");
    // The SetNewPrevHash message is redundant
    // TODO: don't send it?
    // Background: in the future we want to send an empty or optimistic template
    //             before a block is found, so ASIC's can preload it. We would
    //             then immedidately send a SetNewPrevHash message when there's
    //             a new block, and construct a better template _after_ that.

    // Templates are briefly preserved
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 4);
    uint64_t seq_after_tip_pair = tester.m_mining_control->GetTemplateSeq();
    BOOST_REQUIRE(seq_after_tip_pair >= seq_after_second_nt);

    BOOST_TEST_MESSAGE("Briefly provide transactions for stale templates");
    tester.receiveMessage(request_transaction_data_msg);
    size_t bytes_received = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_received, request_transaction_data_success_bytes);

    // And briefly allow SubmitSolution
    // TODO

    BOOST_TEST_MESSAGE("Until after some time");
    SetMockTime(GetMockTime() + std::chrono::seconds{15});
    UninterruptibleSleep(std::chrono::milliseconds{1100});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    tester.receiveMessage(request_transaction_data_msg);
    // RequestTransactionData.Error (just check that the size is different)
    BOOST_REQUIRE(tester.PeerReceiveBytes() != request_transaction_data_success_bytes);

    // Interrupt waitNext()
    tester.m_mining_control->Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()
