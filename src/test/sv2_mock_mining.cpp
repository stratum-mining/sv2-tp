// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_mock_mining.h>

#include <sync.h>
#include <cassert>
#include <logging.h>

namespace {
static inline uint256 HashFromHeight(uint64_t h)
{
    uint256 out;
    for (int i = 0; i < 8; ++i) out.data()[i] = static_cast<unsigned char>((h >> (8 * i)) & 0xFF);
    return out;
}
} // namespace

MockBlockTemplate::MockBlockTemplate(std::shared_ptr<MockState> st, uint256 prev, std::vector<CTransactionRef> txs, uint64_t seq)
    : state(std::move(st)), m_sequence(seq)
{
    // Simple internal consistency assertion: constructor sequence should not exceed state counter.
    assert(m_sequence <= state->chain.template_seq);
    // Build a realistic coinbase with multiple outputs
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << OP_0;

    cb.vout.resize(3);
    // Output 0: Dummy anyone-can-spend output with full reward (will be filtered out by sv2-tp)
    cb.vout[0].nValue = 50 * COIN;
    cb.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Output 1: Fake witness commitment (will be included)
    cb.vout[1].nValue = 0;
    cb.vout[1].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(32, 0xaa);

    // Output 2: Fake merge mining commitment (will be included)
    cb.vout[2].nValue = 0;
    cb.vout[2].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{'M', 'M'};

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
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds{static_cast<int64_t>(options.timeout.count())};
    std::unique_lock<Mutex> lk(state->m);
    while (true) {
        auto predicate = [&] { return state->shutdown || !state->events.empty(); };
        if (!state->cv.wait_until(lk, deadline, predicate)) {
            return nullptr; // timeout
        }
        if (state->shutdown) return nullptr;
        if (state->events.empty()) continue; // spurious
        MockEvent ev = state->events.front();
        state->events.pop();
        bool emit = false;
        if (ev.type == MockEvent::Type::NewTip) {
            state->chain.height++;
            state->chain.prev_hash = HashFromHeight(state->chain.height);
            emit = true; // always emit on new tip
        }
        if (ev.type == MockEvent::Type::FeeIncrease) {
            // Simulate fee increase: bump pending fee sum by +1000 sat per event regardless of tx count
            state->chain.pending_fee_sum += 1000;
            if (!ev.txs.empty()) state->txs = ev.txs;
            const uint64_t delta = state->chain.pending_fee_sum - state->chain.last_template_fee_sum;
            if (delta >= static_cast<uint64_t>(std::max<CAmount>(0, options.fee_threshold))) {
                emit = true;
            }
        }
        if (!emit) {
            // Not enough fee delta yet; continue waiting (loop)
            continue;
        }
        auto prev = state->chain.prev_hash;
        auto txs = state->txs;
        uint64_t seq = ++state->chain.template_seq;
        state->chain.last_template_fee_sum = state->chain.pending_fee_sum;
        state->cv.notify_all(); // wake WaitForTemplateSeq waiters
        lk.unlock();
        return std::make_unique<MockBlockTemplate>(state, prev, std::move(txs), seq);
    }
}

 void MockBlockTemplate::interruptWait()
{
     LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "mock interruptWait()");
}

MockMining::MockMining(std::shared_ptr<MockState> st) : state(std::move(st)) {}
bool MockMining::isTestChain() { return true; }
bool MockMining::isInitialBlockDownload() { return false; }
std::optional<interfaces::BlockRef> MockMining::getTip() { return std::nullopt; }
std::optional<interfaces::BlockRef> MockMining::waitTipChanged(uint256, MillisecondsDouble) { return std::nullopt; }
std::unique_ptr<interfaces::BlockTemplate> MockMining::createNewBlock(const node::BlockCreateOptions&)
{
    LOCK(state->m);
    uint64_t seq = ++state->chain.template_seq;
    return std::make_unique<MockBlockTemplate>(state, state->chain.prev_hash, state->txs, seq);
}
bool MockMining::checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) { return true; }

MemoryLoad MockMining::getMemoryLoad()
{
    return {
        .usage = 0
    };
}

uint64_t MockMining::GetTemplateSeq()
{
    LOCK(state->m);
    return state->chain.template_seq;
}

uint64_t MockMining::GetHeight()
{
    LOCK(state->m);
    return state->chain.height;
}

bool MockMining::WaitForTemplateSeq(uint64_t target, std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&]{ return state->shutdown || state->chain.template_seq >= target; }) && !state->shutdown && state->chain.template_seq >= target;
}

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
