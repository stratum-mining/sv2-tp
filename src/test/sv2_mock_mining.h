// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_MOCK_MINING_H
#define BITCOIN_TEST_SV2_MOCK_MINING_H

#include <interfaces/mining.h>
#include <script/script.h>
#include <sync.h>
#include <uint256.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

// Minimal mocks for the Mining IPC interface used by sv2 tests.

struct MockEvent {
    enum class Type { None, FeeIncrease, NewTip };
    Type type{Type::None};
    std::vector<CTransactionRef> txs; // optional txs on fee increase
};

struct MockState {
    Mutex m;
    uint64_t tip_height{0};
    uint256 prev_hash{uint256()};
    std::vector<CTransactionRef> txs; // non-coinbase
    std::queue<MockEvent> events;
    std::condition_variable_any cv;
    bool shutdown{false};
};

class MockBlockTemplate : public interfaces::BlockTemplate {
public:
    explicit MockBlockTemplate(std::shared_ptr<MockState> st, uint256 prev, std::vector<CTransactionRef> txs);

    CBlockHeader getBlockHeader() override;
    CBlock getBlock() override;
    std::vector<CAmount> getTxFees() override;
    std::vector<int64_t> getTxSigops() override;
    CTransactionRef getCoinbaseTx() override;
    std::vector<unsigned char> getCoinbaseCommitment() override;
    int getWitnessCommitmentIndex() override;
    std::vector<uint256> getCoinbaseMerklePath() override;
    bool submitSolution(uint32_t, uint32_t, uint32_t, CTransactionRef) override;

    std::unique_ptr<interfaces::BlockTemplate> waitNext(const node::BlockWaitOptions options = {}) override;

private:
    std::shared_ptr<MockState> state;
    CBlock block;
};

class MockMining : public interfaces::Mining {
public:
    explicit MockMining(std::shared_ptr<MockState> st);
    bool isTestChain() override;
    bool isInitialBlockDownload() override;
    std::optional<interfaces::BlockRef> getTip() override;
    std::optional<interfaces::BlockRef> waitTipChanged(uint256, MillisecondsDouble) override;
    std::unique_ptr<interfaces::BlockTemplate> createNewBlock(const node::BlockCreateOptions&) override;
    bool checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) override;

    // Test control helpers
    void TriggerFeeIncrease(std::vector<CTransactionRef> txs);
    void TriggerNewTip();
    void Shutdown();

private:
    std::shared_ptr<MockState> state;
};

// Helper to build a simple dummy transaction for tests
CTransactionRef MakeDummyTx();

#endif // BITCOIN_TEST_SV2_MOCK_MINING_H
