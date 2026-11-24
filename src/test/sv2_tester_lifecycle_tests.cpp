// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/test/unit_test.hpp>

#include <interfaces/mining.h>
#include <ipc/exception.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <sv2/block_options.h>
#include <sv2/template_provider.h>
#include <sync.h>
#include <test/sv2_mock_mining.h>
#include <test/sv2_test_setup.h>          // Sv2BasicTestingSetup fixture
#include <test/sv2_tp_tester.h>
#include <uint256.h>

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

/*
 * Regression / lifecycle test: construct and destruct TPTester multiple times
 * to ensure clean shutdown of the EventLoop, IPC proxies, and Template Provider.
 * This aims to catch reference counting or lingering thread issues early.
 */
BOOST_FIXTURE_TEST_SUITE(sv2_tester_lifecycle_tests, Sv2BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ipc_failure_reaches_caller)
{
    TPTester tester{};
    tester.m_state->fail_get_tip = true;
    // The server throws std::runtime_error. It must reach this IPC client as
    // ipc::Exception through the event loop's logging callback.
    BOOST_CHECK_EXCEPTION(tester.m_mining_proxy->getTip(), ipc::Exception, [](const ipc::Exception& e) {
        return std::string_view{e.what()}.find("mock getTip failure") != std::string_view::npos;
    });
    tester.m_state->fail_get_tip = false;
    BOOST_CHECK(!tester.m_mining_proxy->getTip().has_value());
}

BOOST_AUTO_TEST_CASE(tx_lookup_returns_null_for_unknown)
{
    // Make the second transaction a different one, and give it a witness so
    // that its wtxid differs from its txid.
    const CTransactionRef tx_a{MakeDummyTx()};
    CMutableTransaction mtx{*tx_a};
    mtx.nLockTime = 1;
    mtx.vin[0].scriptWitness.stack.push_back({0x01});
    const CTransactionRef tx_b{MakeTransactionRef(mtx)};
    BOOST_REQUIRE(tx_b->GetWitnessHash().ToUint256() != tx_b->GetHash().ToUint256());

    TPTester tester{};
    {
        LOCK(tester.m_state->m);
        tester.m_state->txs = {tx_a, tx_b};
    }
    interfaces::Mining& mining{*tester.m_mining_proxy};

    // The result has one entry per requested txid, in the same order. A
    // transaction the node does not have is sent as empty Data and must be
    // read back as nullptr, see CustomHasField() in ipc/capnp/common-types.h.
    const auto check{[&](const std::vector<CTransactionRef>& txs) {
        BOOST_REQUIRE_EQUAL(txs.size(), 4U);
        BOOST_REQUIRE(txs[0]);
        BOOST_CHECK(*txs[0] == *tx_b);
        BOOST_CHECK(txs[0]->HasWitness());
        BOOST_CHECK(!txs[1]);
        BOOST_REQUIRE(txs[2]);
        BOOST_CHECK(*txs[2] == *tx_a);
        BOOST_CHECK(!txs[3]);
    }};

    // The wtxid of a transaction with a witness is not a txid.
    const Txid unknown_txid{Txid::FromUint256(uint256{1})};
    const Txid not_a_txid{Txid::FromUint256(tx_b->GetWitnessHash().ToUint256())};
    check(mining.getTransactionsByTxID({tx_b->GetHash(), unknown_txid, tx_a->GetHash(), not_a_txid}));
    BOOST_CHECK(mining.getTransactionsByTxID({}).empty());
}

BOOST_AUTO_TEST_CASE(old_node_lacks_newer_methods)
{
    // A simulated Bitcoin Core v31 node, whose Mining interface ends at
    // interrupt(), fails calls to the methods that were added later.
    TPTester tester{Sv2TemplateProviderOptions{.is_test = true}, MockNodeVersion::V31};
    const auto not_implemented{[](const ipc::Exception& e) {
        return std::string_view{e.what()}.find("Method not implemented.") != std::string_view::npos;
    }};
    std::string reason, debug;
    BOOST_CHECK_EXCEPTION(tester.m_mining_proxy->submitBlock(CBlock{}, reason, debug), ipc::Exception, not_implemented);
    BOOST_CHECK_EXCEPTION(tester.m_mining_proxy->getTransactionsByTxID({}), ipc::Exception, not_implemented);
    // The methods it does have still reach the node.
    BOOST_CHECK(!tester.m_mining_proxy->isInitialBlockDownload());
}

BOOST_AUTO_TEST_CASE(mining_interrupt_unblocks_template_creation)
{
    TPTester tester{};
    tester.m_mining_control->PauseCreate(true);
    auto create{std::async(std::launch::async, [&] {
        return tester.m_mining_proxy->createNewBlock(node::BlockCreateOptions{});
    })};
    BOOST_REQUIRE(tester.m_mining_control->WaitForCreateCalls(1));

    tester.m_mining_proxy->interrupt();
    BOOST_CHECK(create.wait_for(std::chrono::milliseconds{1500}) == std::future_status::ready);
    BOOST_CHECK(!create.get());
    // Mining interruption is distinct from node shutdown.
    LOCK(tester.m_state->m);
    BOOST_CHECK(!tester.m_state->shutdown);
}

BOOST_AUTO_TEST_CASE(tp_interrupt_unblocks_wait_next)
{
    Sv2TemplateProviderOptions opts;
    opts.is_test = false;
    opts.template_interval = std::chrono::seconds{5};
    TPTester tester{opts};
    tester.handshake();
    tester.SendSetupConnection();
    tester.SendCoinbaseOutputConstraints();
    tester.ReceiveTemplatePair();
    BOOST_REQUIRE(tester.m_mining_control->WaitForWaitNext());

    // Exercise interruptWait() over IPC before fixture teardown can unblock
    // waitNext() through the direct mock shutdown. Mining::interrupt() alone
    // must not release this wait.
    const auto interrupt_start{std::chrono::steady_clock::now()};
    tester.m_tp->Interrupt();
    tester.m_tp->StopThreads();
    const auto interrupt_elapsed_ms{std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - interrupt_start).count()};
    BOOST_CHECK_MESSAGE(interrupt_elapsed_ms < 1500, "Interrupting waitNext() took " << interrupt_elapsed_ms << "ms");
    LOCK(tester.m_state->m);
    BOOST_CHECK(!tester.m_state->shutdown);
    BOOST_CHECK_EQUAL(tester.m_state->wait_next_waiters, 0);
    BOOST_CHECK_GT(tester.m_state->wait_interrupt_generation, 0U);
}

BOOST_AUTO_TEST_CASE(tp_tester_repeated_construction)
{
    // Run a few iterations; keep count modest to stay fast in CI while
    // still exercising repeated setup/teardown paths.
    constexpr int ITERS = 2;
    for (int i = 0; i < ITERS; ++i) {
        BOOST_TEST_MESSAGE("Lifecycle iteration " << i);
        {
            Sv2TemplateProviderOptions opts;
            opts.is_test = false;
            opts.template_interval = std::chrono::seconds{5};

            auto tester{std::make_unique<TPTester>(opts)};
            // Perform a minimal handshake + setup so the Template Provider
            // allocates resources and creates at least one client connection.
            tester->handshake();

            tester->SendSetupConnection();
            tester->SendCoinbaseOutputConstraints();
            tester->ReceiveTemplatePair();

            BOOST_REQUIRE(tester->m_mining_control->WaitForWaitNext());

            const auto destroy_start{std::chrono::steady_clock::now()};
            tester.reset();
            const auto destroy_elapsed{std::chrono::steady_clock::now() - destroy_start};
            const auto destroy_elapsed_ms{std::chrono::duration_cast<std::chrono::milliseconds>(destroy_elapsed).count()};
            BOOST_CHECK_MESSAGE(destroy_elapsed_ms < 1500, "TPTester teardown took " << destroy_elapsed_ms << "ms");
        }
        // The explicit reset above should cleanly tear down.
        // If any dangling references or threads exist they should surface as
        // test hangs or use-after-frees under sanitizers / valgrind.
    }
}

BOOST_AUTO_TEST_SUITE_END()
