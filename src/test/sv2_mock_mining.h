// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_MOCK_MINING_H
#define BITCOIN_TEST_SV2_MOCK_MINING_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

#include <interfaces/mining.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <uint256.h>

using interfaces::MemoryLoad;

// Minimal mocks for the Mining IPC interface used by sv2 tests.

struct MockEvent {
    enum class Type { None, FeeIncrease };
    Type type{Type::None};
    std::vector<CTransactionRef> txs; // optional txs on fee increase
};

/**
 * Simple representation of chain-related data for the mock. This makes it
 * easier to extend (e.g. adding MTP, work, feature bits) without touching the
 * rest of the state users.
 */
struct ChainState {
    uint64_t height{0};        // current chain height (genesis = 0)
    uint256 prev_hash{uint256()}; // hash of current tip (used as prev of next template)
    uint64_t template_seq{0};  // monotonically increasing sequence for templates
    uint64_t last_template_fee_sum{0}; // simulated total fees of last emitted template
    uint64_t pending_fee_sum{0};       // simulated total fees after last fee increase event
};

struct MockState {
    Mutex m;
    //! Make getTip() fail on the IPC server.
    std::atomic<bool> fail_get_tip{false};
    //! Make submitSolution() reject the block.
    std::atomic<bool> reject_solution{false};
    //! Number of calls to each submitSolution() variant, including calls that
    //! throw because the mock node does not have the method.
    std::atomic<int> submit_solution_calls{0};
    std::atomic<int> submit_solution_old7_calls{0};
    ChainState chain;                // grouped chain data
    std::vector<CTransactionRef> txs; // non-coinbase transactions included in templates
    std::queue<MockEvent> events;    // queued events driving waitNext()
    std::condition_variable_any cv;
    int wait_next_waiters{0};
    MemoryLoad memory_load;
    bool shutdown{false};
    uint64_t wait_interrupt_generation{0};
};

class MockBlockTemplate : public interfaces::BlockTemplate {
public:
    explicit MockBlockTemplate(std::shared_ptr<MockState> st, uint256 prev, std::vector<CTransactionRef> txs, uint64_t seq, CAmount total_fees);

    // Accessor for tests (future use). Keeps sequence from being flagged unused.
    uint64_t sequence() const { return m_sequence; }

    CBlockHeader getBlockHeader() override;
    CBlock getBlock() override;
    std::vector<CAmount> getTxFees() override;
    std::vector<int64_t> getTxSigops() override;
    node::CoinbaseTx getCoinbaseTx() override;
    std::vector<uint256> getCoinbaseMerklePath() override;
    bool submitSolution(uint32_t, uint32_t, uint32_t, CTransactionRef, std::string&, std::string&) override;
    bool submitSolutionOld7(uint32_t, uint32_t, uint32_t, CTransactionRef) override;

    std::unique_ptr<interfaces::BlockTemplate> waitNext(node::BlockWaitOptions options = {}) override;
    void interruptWait() override;

private:
    std::shared_ptr<MockState> state;
    CBlock block;
    uint64_t m_sequence{0}; // internal sequence number (not exposed yet, reserved for future assertions)

    // The mock tracks only aggregate template fees, enough for the SV2
    // fee-delta checks without modelling per-transaction fee accounting.
    CAmount m_total_fees{0};
};

class MockMining : public interfaces::Mining {
public:
    explicit MockMining(std::shared_ptr<MockState> st);
    bool isTestChain() override;
    bool isInitialBlockDownload() override;
    std::optional<interfaces::BlockRef> getTip() override;
    std::optional<interfaces::BlockRef> waitTipChanged(uint256, MillisecondsDouble) override;
    std::unique_ptr<interfaces::BlockTemplate> createNewBlock(const node::BlockCreateOptions&, bool cooldown) override;
    void interrupt() override;
    bool checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) override;
    bool submitBlock(const CBlock&, std::string&, std::string&) override;
    std::vector<CTransactionRef> getTransactionsByTxID(const std::vector<Txid>&) override;
    std::vector<CTransactionRef> getTransactionsByWitnessID(const std::vector<Wtxid>&) override { return {}; }
    MemoryLoad getMemoryLoad() override;

    // Accessors for tests (thread-safe)
    uint64_t GetTemplateSeq();
    uint64_t GetHeight();

    // Test control helpers
    void TriggerFeeIncrease(std::vector<CTransactionRef> txs);
    //! Advance the chain tip. Like the real node, this is observed by every
    //! concurrent waitNext() caller, each of which returns a template for the
    //! new tip.
    void TriggerNewTip();
    void SetMemoryLoad(uint64_t usage);
    void Shutdown();

    // Wait until internal template sequence reaches at least target (returns false on timeout/shutdown)
    bool WaitForTemplateSeq(uint64_t target, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000});
    // Wait until at least min_waiters threads are blocked in waitNext (returns false on timeout/shutdown)
    bool WaitForWaitNext(int min_waiters = 1, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000});

private:
    std::shared_ptr<MockState> state;
};

// Helper to build a simple dummy transaction for tests
CTransactionRef MakeDummyTx();

#endif // BITCOIN_TEST_SV2_MOCK_MINING_H
