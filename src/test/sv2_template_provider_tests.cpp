#include <boost/test/unit_test.hpp>
#include <interfaces/init.h>
#include <interfaces/mining.h>
#include <ipc/exception.h>
#include <sv2/block_options.h>
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
#include <test/sv2_mock_mining.h>
#include <test/sv2_tp_tester.h>

#include <algorithm>
#include <exception>
#include <future>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>

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

BOOST_AUTO_TEST_CASE(multiple_template_pair_trigger)
{
    TPTester tester{};

    tester.handshake();
    tester.SendSetupConnection();

    // Send initial SendCoinbaseOutputConstraints to receive the first TemplatePair
    tester.SendCoinbaseOutputConstraints();
    tester.ReceiveTemplatePair();

    BOOST_REQUIRE(tester.m_mining_control->WaitForWaitNext());

    // Send another SendCoinbaseOutputConstraints to receive second ReceiveTemplatePair
    tester.SendCoinbaseOutputConstraints();
    tester.ReceiveTemplatePair();
}

BOOST_AUTO_TEST_CASE(client_tests)
{
    TPTesterHandle tester_handle{};
    TPTester& tester = *tester_handle;

    tester.handshake();

    // After the handshake the client must send a SetupConnection message to the
    // Template Provider.
    BOOST_TEST_MESSAGE("Handshake done, send SetupConnectionMsg");
    tester.SendSetupConnection();

    // There should be no block templates before any client gave us their coinbase
    // output data size:
    BOOST_REQUIRE(tester.GetBlockTemplateCount() == 0);

    tester.SendCoinbaseOutputConstraints();
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
    SetMockTime(GetMockTime() + std::chrono::seconds{tester.m_tp_options.template_interval});

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
    SetMockTime(GetMockTime() + std::chrono::seconds{tester.m_tp_options.template_interval});

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

// The node version is determined when the template provider starts.
BOOST_AUTO_TEST_CASE(node_version_detection)
{
    {
        TPTester tester{Sv2TemplateProviderOptions{.is_test = true}, MockNodeVersion::CURRENT};
        BOOST_CHECK_EQUAL(tester.m_tp->GetNodeVersion(), NODE_VERSION_32_00);
        tester.m_mining_control->Shutdown();
    }
    {
        BOOST_TEST_MESSAGE("Simulate a Bitcoin Core v31 node");
        TPTester tester{Sv2TemplateProviderOptions{.is_test = true}, MockNodeVersion::V31};
        BOOST_CHECK_EQUAL(tester.m_tp->GetNodeVersion(), NODE_VERSION_31_0);
        tester.m_mining_control->Shutdown();
    }
}

BOOST_AUTO_TEST_CASE(node_version_detection_propagates_errors)
{
    struct FailingMining : MockMining {
        using MockMining::MockMining;
        std::exception_ptr error;
        std::vector<CTransactionRef> getTransactionsByTxID(const std::vector<Txid>&) override
        {
            std::rethrow_exception(error);
        }
    };

    const auto check_error = [](const auto& error) {
        FailingMining mining{std::make_shared<MockState>()};
        mining.error = std::make_exception_ptr(error);
        Sv2TemplateProvider tp{mining};
        BOOST_CHECK_EXCEPTION((void)tp.Start(Sv2TemplateProviderOptions{.is_test = true}), std::decay_t<decltype(error)>, [&error](const auto& e) {
            return std::string{e.what()} == error.what();
        });
    };

    check_error(ipc::Exception{"IPC client method call interrupted by disconnect."});
    check_error(ipc::Exception{"kj::Exception: remote exception: getTransactionsByTxID failed"});
    // The diagnostic alone is insufficient without the IPC exception type.
    check_error(std::runtime_error{"Method not implemented."});
}

// Solutions are submitted with the current submitSolution() method, unless the
// node only has the deprecated one, as is the case for Bitcoin Core v31.
BOOST_AUTO_TEST_CASE(submit_solution_interface_version)
{
    const struct {
        MockNodeVersion version;
        const char* description;
        int expected_calls;      // calls to submitSolution()
        int expected_old7_calls; // calls to submitSolutionOld7()
    } cases[]{
        {MockNodeVersion::CURRENT, "Simulate a recent node", 1, 0},
        {MockNodeVersion::V31, "Simulate a Bitcoin Core v31 node", 0, 1},
    };

    for (const auto& test_case : cases) {
        BOOST_TEST_MESSAGE(test_case.description);
        TPTester tester{Sv2TemplateProviderOptions{.is_test = true}, test_case.version};

        tester.handshake();
        tester.SendSetupConnection();
        tester.SendCoinbaseOutputConstraints();
        tester.ReceiveTemplatePair();

        node::Sv2SubmitSolutionMsg solution;
        solution.m_template_id = 1;
        solution.m_version = 1;
        solution.m_header_timestamp = 0;
        solution.m_header_nonce = 0;
        solution.m_coinbase_tx = CMutableTransaction{*MakeDummyTx()};

        tester.m_tp->SubmitSolution(solution);

        BOOST_CHECK_EQUAL(tester.m_state->submit_solution_calls.load(), test_case.expected_calls);
        BOOST_CHECK_EQUAL(tester.m_state->submit_solution_old7_calls.load(), test_case.expected_old7_calls);

        // Let the sv2-saveblk thread finish, it uses the IPC connection.
        UninterruptibleSleep(std::chrono::milliseconds{1000});

        tester.m_mining_control->Shutdown();
    }
}

// After a tip change, every connected client must receive NewTemplate
// (future_template=true) followed by the matching SetNewPrevHash — not just
// the client whose handler processes the new tip first.
// Regression test for https://github.com/stratum-mining/sv2-tp/issues/111
BOOST_AUTO_TEST_CASE(two_clients_receive_set_new_prev_hash)
{
    TPTester tester{};

    // Connect two clients; each gets an initial NewTemplate + SetNewPrevHash.
    for (size_t peer_id = 0; peer_id < 2; ++peer_id) {
        tester.handshake(peer_id);
        tester.SendSetupConnection(peer_id);
        tester.SendCoinbaseOutputConstraints(peer_id);
        tester.ReceiveTemplatePair(peer_id);
    }

    // Wait until both client handler threads are waiting for template updates.
    BOOST_REQUIRE(tester.m_mining_control->WaitForWaitNext(/*min_waiters=*/2));

    uint64_t seq = tester.m_mining_control->GetTemplateSeq();

    BOOST_TEST_MESSAGE("Create a new block (new tip)");
    tester.m_mining_control->TriggerNewTip();

    // Both handlers must build a template for the new tip...
    BOOST_REQUIRE(tester.m_mining_control->WaitForTemplateSeq(seq + 2));

    // ...and both clients must receive NewTemplate + SetNewPrevHash.
    tester.ReceiveTemplatePair(0);
    tester.ReceiveTemplatePair(1);

    tester.m_mining_control->Shutdown();
}

// Regression test for https://github.com/stratum-mining/sv2-tp/issues/129.
// Concurrent handlers must send the ID allocated to their own cached template.
BOOST_AUTO_TEST_CASE(multiple_clients_receive_own_template_id)
{
    TPTester tester{};
    constexpr size_t NUM_CLIENTS{6};
    std::set<uint64_t> template_ids;

    const auto receive_and_check = [&](size_t peer_id) {
        const uint64_t template_id{tester.ReceiveTemplatePair(peer_id)};
        BOOST_REQUIRE_MESSAGE(template_ids.insert(template_id).second, "Clients received a duplicate template ID");

        const uint256 tip{WITH_LOCK(tester.m_state->m, return tester.m_state->chain.prev_hash;)};
        LOCK(tester.m_tp->m_tp_mutex);
        const auto& templates{tester.m_tp->GetBlockTemplates()};
        const auto cached{templates.find(template_id)};
        BOOST_REQUIRE_MESSAGE(cached != templates.end(), "Received template ID is not cached");
        BOOST_REQUIRE(cached->second.first == tip);
    };

    for (size_t peer_id = 0; peer_id < NUM_CLIENTS; ++peer_id) {
        tester.handshake(peer_id);
        tester.SendSetupConnection(peer_id);
        tester.SendCoinbaseOutputConstraints(peer_id);
        receive_and_check(peer_id);
    }

    // Exercise repeated tip changes, when all handlers build templates together.
    for (int tip = 0; tip < 10; ++tip) {
        BOOST_REQUIRE(tester.m_mining_control->WaitForWaitNext(NUM_CLIENTS));
        const uint64_t seq{tester.m_mining_control->GetTemplateSeq()};
        tester.m_mining_control->TriggerNewTip();
        BOOST_REQUIRE(tester.m_mining_control->WaitForTemplateSeq(seq + NUM_CLIENTS));
        for (size_t peer_id = 0; peer_id < NUM_CLIENTS; ++peer_id) {
            receive_and_check(peer_id);
        }
    }

    tester.m_mining_control->Shutdown();
}

// Test fee-based rate limiting timer (-templateinterval flag).
// Uses is_test=false to exercise actual timer logic.
BOOST_AUTO_TEST_CASE(fee_timer_blocking_test)
{
    // Use real wall-clock time instead of mock time
    SetMockTime(std::chrono::seconds{0});

    Sv2TemplateProviderOptions opts;
    opts.is_test = false;
    opts.template_interval = std::chrono::seconds{2};
    TPTesterHandle tester_handle{opts};
    TPTester& tester = *tester_handle;

    tester.handshake();
    tester.SendSetupConnection();
    tester.SendCoinbaseOutputConstraints();
    tester.ReceiveTemplatePair();

    const size_t expected_new_template = SV2_HEADER_ENCRYPTED_SIZE + TPTester::SV2_NEW_TEMPLATE_MSG_SIZE + Poly1305::TAGLEN;

    uint64_t seq = tester.m_mining_control->GetTemplateSeq();

    // Trigger a fee increase immediately after template; timer should block it
    BOOST_TEST_MESSAGE("Trigger fee increase while timer is blocking");
    std::vector<CTransactionRef> blocked_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(blocked_fee_txs);

    bool got_template = tester.m_mining_control->WaitForTemplateSeq(seq + 1, std::chrono::milliseconds{2500});
    BOOST_REQUIRE_MESSAGE(!got_template, "Fee increase should be blocked when timer hasn't fired");
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // After template_interval (2s), the timer should allow fee checks
    BOOST_TEST_MESSAGE("Trigger fee increase after timer fires");
    std::vector<CTransactionRef> allowed_fee_txs{MakeDummyTx()};
    tester.m_mining_control->TriggerFeeIncrease(allowed_fee_txs);

    got_template = tester.m_mining_control->WaitForTemplateSeq(seq + 1, std::chrono::milliseconds{3000});
    BOOST_REQUIRE_MESSAGE(got_template, "Fee increase should be allowed after timer fires");

    size_t bytes_nt = tester.PeerReceiveBytes();
    BOOST_REQUIRE_EQUAL(bytes_nt, expected_new_template);
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 2);

    tester.m_mining_control->Shutdown();
}

// New tips must always produce a template, even when the fee timer is blocking.
BOOST_AUTO_TEST_CASE(new_tip_bypasses_fee_timer_test)
{
    SetMockTime(std::chrono::seconds{0});

    Sv2TemplateProviderOptions opts;
    opts.is_test = false;
    opts.template_interval = std::chrono::seconds{10};
    TPTesterHandle tester_handle{opts};
    TPTester& tester = *tester_handle;

    tester.handshake();
    tester.SendSetupConnection();
    tester.SendCoinbaseOutputConstraints();
    tester.ReceiveTemplatePair();

    uint64_t seq = tester.m_mining_control->GetTemplateSeq();

    // Timer just reset (10s interval). A new tip should still produce a
    // template immediately, bypassing the fee timer.
    BOOST_TEST_MESSAGE("Trigger new tip while fee timer is blocking");
    tester.m_mining_control->TriggerNewTip();

    bool got_template = tester.m_mining_control->WaitForTemplateSeq(seq + 1, std::chrono::milliseconds{3000});
    BOOST_REQUIRE_MESSAGE(got_template, "New tip should bypass fee timer and produce a template");
    tester.ReceiveTemplatePair();
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 2);

    tester.m_mining_control->Shutdown();
}

// The network layer forwards SubmitSolution even when the client skipped
// CoinbaseOutputConstraints, because dropping a solution could cost a block.
// Make sure that's safe: without a template to match, the template provider
// ignores the solution.
BOOST_AUTO_TEST_CASE(submit_solution_without_template)
{
    Sv2LogCapture logs;
    TPTester tester{};

    tester.handshake();
    tester.SendSetupConnection();
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 0);

    node::Sv2NetMsg solution{TestSubmitSolutionMsg()};
    tester.receiveMessage(solution);
    BOOST_REQUIRE(logs.WaitFor("Received SubmitSolution before SetupConnection and CoinbaseOutputConstraints"));
    BOOST_REQUIRE(logs.WaitFor("Template with id=2 is no longer in cache"));
}

BOOST_AUTO_TEST_SUITE_END()
