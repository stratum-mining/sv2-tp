// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_mock_mining.h>

#include <sync.h>
#include <cassert>
#include <logging.h>
#include <sv2/messages.h>

namespace {
static inline uint256 HashFromHeight(uint64_t h)
{
    uint256 out;
    for (int i = 0; i < 8; ++i) out.data()[i] = static_cast<unsigned char>((h >> (8 * i)) & 0xFF);
    return out;
}
} // namespace

MockBlockTemplate::MockBlockTemplate(std::shared_ptr<MockState> st, uint256 prev, std::vector<CTransactionRef> txs, uint64_t seq, CAmount total_fees)
    : state(std::move(st)), m_sequence(seq), m_total_fees(total_fees)
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
std::vector<CAmount> MockBlockTemplate::getTxFees()
{
    // The real interface exposes fees per transaction. Tests only need the
    // total fee sum to exercise waitNext fee-threshold behavior, so expose it
    // as a single aggregate entry.
    return m_total_fees > 0 ? std::vector<CAmount>{m_total_fees} : std::vector<CAmount>{};
}
std::vector<int64_t> MockBlockTemplate::getTxSigops() { return {}; }
node::CoinbaseTx MockBlockTemplate::getCoinbaseTx() { return ExtractCoinbaseTx(block.vtx[0]); }
std::vector<uint256> MockBlockTemplate::getCoinbaseMerklePath() { return {}; }
bool MockBlockTemplate::submitSolution(uint32_t, uint32_t, uint32_t, CTransactionRef) { return true; }

std::unique_ptr<interfaces::BlockTemplate> MockBlockTemplate::waitNext(node::BlockWaitOptions options)
{
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds{static_cast<int64_t>(options.timeout.count())};
    std::unique_lock<Mutex> lk(state->m);
    struct WaitNextWaiter {
        explicit WaitNextWaiter(MockState& state) : m_state(state)
        {
            ++m_state.wait_next_waiters;
            m_state.cv.notify_all();
        }

        ~WaitNextWaiter()
        {
            --m_state.wait_next_waiters;
            m_state.cv.notify_all();
        }

        MockState& m_state;
    } waiter{*state};

    ++state->wait_next_calls;
    state->cv.notify_all();
    const uint64_t observed_interrupt_generation{state->wait_interrupt_generation};
    while (true) {
        auto predicate = [&] {
            return state->shutdown ||
                   state->return_null_wait_next ||
                   state->wait_interrupt_generation != observed_interrupt_generation ||
                   !state->events.empty();
        };
        if (!state->cv.wait_until(lk, deadline, predicate)) {
            return nullptr; // timeout
        }
        if (state->shutdown) {
            return nullptr;
        }
        if (state->return_null_wait_next) {
            return nullptr;
        }
        if (state->wait_interrupt_generation != observed_interrupt_generation) {
            return nullptr;
        }
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
            // Model fee inflow independently from tx contents so tests can
            // deterministically trigger or suppress fee-threshold templates.
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
        return std::make_unique<MockBlockTemplate>(state, prev, std::move(txs), seq, state->chain.pending_fee_sum);
    }
}

void MockBlockTemplate::interruptWait()
{
    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "mock interruptWait()");
    LOCK(state->m);
    ++state->wait_interrupt_generation;
    state->cv.notify_all();
}

MockMining::MockMining(std::shared_ptr<MockState> st) : state(std::move(st)) {}
bool MockMining::isTestChain() { return true; }
bool MockMining::isInitialBlockDownload()
{
    LOCK(state->m);
    ++state->initial_block_download_checks;
    state->cv.notify_all();
    return false;
}
std::optional<interfaces::BlockRef> MockMining::getTip() { return std::nullopt; }
std::optional<interfaces::BlockRef> MockMining::waitTipChanged(uint256, MillisecondsDouble) { return std::nullopt; }
std::unique_ptr<interfaces::BlockTemplate> MockMining::createNewBlock(const node::BlockCreateOptions&, bool)
{
    LOCK(state->m);
    uint64_t seq = ++state->chain.template_seq;
    return std::make_unique<MockBlockTemplate>(state, state->chain.prev_hash, state->txs, seq, state->chain.pending_fee_sum);
}
void MockMining::interrupt() { LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "mock interrupt()"); }
bool MockMining::checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) { return true; }

uint64_t MockMining::GetInitialBlockDownloadChecks()
{
    LOCK(state->m);
    return state->initial_block_download_checks;
}

uint64_t MockMining::GetWaitNextCalls()
{
    LOCK(state->m);
    return state->wait_next_calls;
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

bool MockMining::WaitForInitialBlockDownloadChecks(uint64_t target, std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&] {
        return state->shutdown || state->initial_block_download_checks >= target;
    }) && !state->shutdown && state->initial_block_download_checks >= target;
}

bool MockMining::WaitForWaitNextCalls(uint64_t target, std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&] {
        return state->shutdown || state->wait_next_calls >= target;
    }) && !state->shutdown && state->wait_next_calls >= target;
}

bool MockMining::WaitForWaitNext(std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&]{ return state->shutdown || state->wait_next_waiters > 0; }) && !state->shutdown && state->wait_next_waiters > 0;
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
void MockMining::SetWaitNextReturnsNull(bool value)
{
    LOCK(state->m);
    state->return_null_wait_next = value;
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
