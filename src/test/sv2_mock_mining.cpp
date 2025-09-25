// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "sv2_mock_mining.h"

#include <sync.h>

namespace {
static inline uint256 HashFromHeight(uint64_t h)
{
    uint256 out;
    for (int i = 0; i < 8; ++i) out.data()[i] = static_cast<unsigned char>((h >> (8 * i)) & 0xFF);
    return out;
}
} // namespace

MockBlockTemplate::MockBlockTemplate(std::shared_ptr<MockState> st, uint256 prev, std::vector<CTransactionRef> txs)
    : state(std::move(st))
{
    // Build a dummy coinbase
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << OP_0;
    cb.vout.resize(1);
    cb.vout[0].nValue = 50 * COIN;
    cb.vout[0].scriptPubKey = CScript() << OP_RETURN;

    block = CBlock{};
    block.vtx.clear();
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));
    for (auto& tx : txs) block.vtx.push_back(tx);
    block.nVersion = 1;
    block.nTime = 0;
    block.nBits = 0;
    block.nNonce = 0;
    block.hashPrevBlock = prev;
}

CBlockHeader MockBlockTemplate::getBlockHeader() { return block.GetBlockHeader(); }
CBlock MockBlockTemplate::getBlock() { return block; }
std::vector<CAmount> MockBlockTemplate::getTxFees() { return {}; }
std::vector<int64_t> MockBlockTemplate::getTxSigops() { return {}; }
CTransactionRef MockBlockTemplate::getCoinbaseTx() { return block.vtx[0]; }
std::vector<unsigned char> MockBlockTemplate::getCoinbaseCommitment() { return {}; }
int MockBlockTemplate::getWitnessCommitmentIndex() { return -1; }
std::vector<uint256> MockBlockTemplate::getCoinbaseMerklePath() { return {}; }
bool MockBlockTemplate::submitSolution(uint32_t, uint32_t, uint32_t, CTransactionRef) { return true; }

std::unique_ptr<interfaces::BlockTemplate> MockBlockTemplate::waitNext(const node::BlockWaitOptions options)
{
    // Wait for an event or timeout
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds{static_cast<int64_t>(options.timeout.count())};
    std::unique_lock<Mutex> lk(state->m);
    auto predicate = [&] { return state->shutdown || !state->events.empty(); };
    if (!state->cv.wait_until(lk, deadline, predicate)) {
        return nullptr; // timeout
    }
    if (state->shutdown) return nullptr;
    MockEvent ev = state->events.front();
    state->events.pop();
    if (ev.type == MockEvent::Type::NewTip) {
        state->tip_height++;
        state->prev_hash = HashFromHeight(state->tip_height);
        // Keep txs as-is on new tip
    }
    if (!ev.txs.empty()) state->txs = ev.txs;
    auto prev = state->prev_hash;
    auto txs = state->txs;
    lk.unlock();
    return std::make_unique<MockBlockTemplate>(state, prev, std::move(txs));
}

MockMining::MockMining(std::shared_ptr<MockState> st) : state(std::move(st)) {}
bool MockMining::isTestChain() { return true; }
bool MockMining::isInitialBlockDownload() { return false; }
std::optional<interfaces::BlockRef> MockMining::getTip() { return std::nullopt; }
std::optional<interfaces::BlockRef> MockMining::waitTipChanged(uint256, MillisecondsDouble) { return std::nullopt; }
std::unique_ptr<interfaces::BlockTemplate> MockMining::createNewBlock(const node::BlockCreateOptions&)
{
    LOCK(state->m);
    return std::make_unique<MockBlockTemplate>(state, state->prev_hash, state->txs);
}
bool MockMining::checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) { return true; }

void MockMining::TriggerFeeIncrease(std::vector<CTransactionRef> txs)
{
    LOCK(state->m);
    state->events.push(MockEvent{MockEvent::Type::FeeIncrease, std::move(txs)});
    state->cv.notify_all();
}
void MockMining::TriggerNewTip()
{
    LOCK(state->m);
    state->events.push(MockEvent{MockEvent::Type::NewTip, {}});
    state->cv.notify_all();
}
void MockMining::Shutdown()
{
    LOCK(state->m);
    state->shutdown = true;
    state->cv.notify_all();
}

CTransactionRef MakeDummyTx()
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_1;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{'t', 'e', 's', 't'};
    return MakeTransactionRef(mtx);
}
