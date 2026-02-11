#include <boost/test/unit_test.hpp>
#include <interfaces/mining.h>
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
#include <memory>
#include <string>
#include <thread>

// TPTester handles IPC glue internally; no need to include IPC headers here

// For verbose debugging use:
// build/src/test/test_sv2 --run_test=sv2_template_provider_tests --log_level=all -- -debug=sv2 -loglevel=sv2:trace | grep -v disabled

BOOST_FIXTURE_TEST_SUITE(sv2_template_provider_tests, Sv2BasicTestingSetup)

BOOST_AUTO_TEST_CASE(client_tests)
{
    TPTester tester{};

    tester.handshake();

    BOOST_TEST_MESSAGE("Handshake done, send SetupConnection and CoinbaseOutputConstraints");
    tester.SendSetupAndCoinbaseConstraints();

    BOOST_TEST_MESSAGE("The reply should be NewTemplate and SetNewPrevHash");
    tester.ReceiveTemplatePair();

    const size_t expected_new_template = SV2_HEADER_ENCRYPTED_SIZE + TPTester::SV2_NEW_TEMPLATE_MSG_SIZE + Poly1305::TAGLEN;

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
    BOOST_REQUIRE_EQUAL(bytes_fee_nt, expected_new_template);

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
    BOOST_REQUIRE_EQUAL(bytes_second_nt, expected_new_template);

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
    tester.ReceiveTemplatePair();
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

// Test the fee-based rate limiting timer behavior.
// This test uses is_test=false to exercise the actual timer logic that is
// normally bypassed in tests. The timer blocks fee-based template updates
// until fee_check_interval seconds have passed (-sv2interval flag).
BOOST_AUTO_TEST_CASE(fee_timer_blocking_test)
{
    // Clear mock time so the Timer uses real wall-clock time.
    // The test fixture sets mock time, which would prevent the timer from
    // advancing without explicit SetMockTime calls.
    SetMockTime(std::chrono::seconds{0});

    // Use is_test=false to test actual timer behavior.
    // Use a short fee_check_interval (2s) to keep the test fast.
    Sv2TemplateProviderOptions opts;
    opts.is_test = false;
    opts.fee_check_interval = std::chrono::seconds{2};
    TPTester tester{opts};

    tester.handshake();
    tester.SendSetupAndCoinbaseConstraints();
    tester.ReceiveTemplatePair();

    const size_t expected_new_template = SV2_HEADER_ENCRYPTED_SIZE + TPTester::SV2_NEW_TEMPLATE_MSG_SIZE + Poly1305::TAGLEN;

    // Timer was reset after the initial template was sent.
    uint64_t seq = tester.m_mining_control->GetTemplateSeq();
    BOOST_TEST_MESSAGE("Initial template sequence: " << seq);

    // Immediately trigger a fee increase. The timer hasn't fired yet (just reset),
    // so this should be blocked (fee_delta = MAX_MONEY, threshold not met).
    BOOST_TEST_MESSAGE("Triggering fee increase while timer is blocking...");
    std::vector<CTransactionRef> blocked_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(blocked_fee_txs);

    // Wait for the mock's waitNext timeout (fee_check_interval = 2s) plus buffer.
    // Should NOT get a new template because the timer blocked fee checks.
    bool got_template = tester.m_mining_control->WaitForTemplateSeq(seq + 1, std::chrono::milliseconds{2500});
    BOOST_REQUIRE_MESSAGE(!got_template, "Fee increase should be blocked when timer hasn't fired");

    // Verify template count is still 1
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Now more than fee_check_interval (2s) has passed since the timer was reset.
    // The timer should fire on the next iteration, allowing fee checks.
    BOOST_TEST_MESSAGE("Triggering fee increase after timer should have fired...");
    std::vector<CTransactionRef> allowed_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(allowed_fee_txs);

    // This time we should get a template. Allow up to 3s since the TP may be
    // partway through a 2s waitNext cycle when we trigger the fee increase.
    got_template = tester.m_mining_control->WaitForTemplateSeq(seq + 1, std::chrono::milliseconds{3000});
    BOOST_REQUIRE_MESSAGE(got_template, "Fee increase should be allowed after timer fires");

    // Receive the NewTemplate message
    size_t bytes_nt = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_nt, expected_new_template);

    // Verify we now have 2 templates
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 2);

    tester.m_mining_control->Shutdown();
}

BOOST_AUTO_TEST_SUITE_END()
