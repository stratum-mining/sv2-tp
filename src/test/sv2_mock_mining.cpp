// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_mock_mining.h>

#include <sync.h>
#include <cassert>
#include <consensus/merkle.h>
#include <logging.h>
#include <sv2/messages.h>
#include <tinyformat.h>

#include <algorithm>
#include <stdexcept>

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

    m_block = CBlock{};
    m_block.vtx.clear();
    m_block.vtx.push_back(MakeTransactionRef(std::move(cb)));
    for (auto& tx : txs) m_block.vtx.push_back(tx);
    m_block.nVersion = 1;
    m_block.nTime = 0;
    m_block.nBits = 0;
    m_block.nNonce = 0;
    m_block.hashPrevBlock = prev;
}

MockBlock::MockBlock(std::shared_ptr<MockState> st, CBlock block) : state(std::move(st)), m_block(std::move(block))
{
    ++state->blocks_alive;
}
MockBlock::~MockBlock() { --state->blocks_alive; }
CBlockHeader MockBlock::header()
{
    ++state->block_header_calls;
    return m_block.GetBlockHeader();
}
CBlock MockBlock::data()
{
    ++state->block_data_calls;
    return m_block;
}
std::vector<uint256> MockBlock::coinbaseMerklePath()
{
    ++state->block_merkle_path_calls;
    return {};
}

CBlockHeader MockBlockTemplate::getBlockHeaderOld1()
{
    ++state->template_header_calls;
    return m_block.GetBlockHeader();
}
std::unique_ptr<interfaces::Block> MockBlockTemplate::block()
{
    ++state->block_calls;
    return std::make_unique<MockBlock>(state, m_block);
}
CBlock MockBlockTemplate::getBlockOld2()
{
    ++state->get_block_old2_calls;
    LOCK(state->m);
    return m_submitted_block.value_or(m_block);
}
std::vector<CAmount> MockBlockTemplate::getTxFees()
{
    // The real interface exposes fees per transaction. Tests only need the
    // total fee sum to exercise waitNext fee-threshold behavior, so expose it
    // as a single aggregate entry.
    return m_total_fees > 0 ? std::vector<CAmount>{m_total_fees} : std::vector<CAmount>{};
}
std::vector<int64_t> MockBlockTemplate::getTxSigops() { return {}; }
node::CoinbaseTx MockBlockTemplate::getCoinbaseTx() { return ExtractCoinbaseTx(m_block.vtx[0]); }
std::vector<uint256> MockBlockTemplate::getCoinbaseMerklePathOld6()
{
    ++state->template_merkle_path_calls;
    return {};
}

CBlock MockBlockTemplate::SolvedBlock(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase) const
{
    CBlock block{m_block};
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.vtx[0] = std::move(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

std::unique_ptr<interfaces::Block> MockBlockTemplate::submitSolution(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase, bool& accepted, std::string& reason, std::string& debug)
{
    ++state->submit_solution_calls;
    if (!coinbase) throw std::invalid_argument("Coinbase transaction must not be null");
    // Like Bitcoin Core, leave the template unchanged and return the block,
    // even if it is rejected.
    accepted = !state->reject_solution;
    if (!accepted) {
        reason = "duplicate";
        debug = "block already known";
    }
    return std::make_unique<MockBlock>(state, SolvedBlock(version, timestamp, nonce, std::move(coinbase)));
}

bool MockBlockTemplate::submitSolutionOld10(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase, std::string& reason, std::string& debug)
{
    ++state->submit_solution_old10_calls;
    if (!coinbase) return false;
    // Like Bitcoin Core v32, modify the template even if the block is rejected.
    WITH_LOCK(state->m, m_submitted_block = SolvedBlock(version, timestamp, nonce, std::move(coinbase)));
    if (state->reject_solution) {
        reason = "duplicate";
        debug = "block already known";
        return false;
    }
    return true;
}

bool MockBlockTemplate::submitSolutionOld7(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase)
{
    ++state->submit_solution_old7_calls;
    if (!coinbase) return false;
    WITH_LOCK(state->m, m_submitted_block = SolvedBlock(version, timestamp, nonce, std::move(coinbase)));
    return !state->reject_solution;
}

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

    const uint64_t observed_interrupt_generation{state->wait_interrupt_generation};
    while (true) {
        auto predicate = [&] {
            return state->shutdown || state->fail_wait_next ||
                   state->wait_interrupt_generation != observed_interrupt_generation ||
                   state->chain.prev_hash != m_block.hashPrevBlock ||
                   !state->events.empty();
        };
        if (!state->cv.wait_until(lk, deadline, predicate)) {
            return nullptr; // timeout
        }
        if (state->shutdown) {
            return nullptr;
        }
        if (state->fail_wait_next) {
            throw std::runtime_error("waitNext failed");
        }
        if (state->wait_interrupt_generation != observed_interrupt_generation) {
            return nullptr;
        }
        if (state->chain.prev_hash != m_block.hashPrevBlock) {
            // The tip changed since this template was built. Like the real
            // waitNext(), every waiter observes this and emits a template for
            // the new tip, regardless of the fee threshold.
            auto prev = state->chain.prev_hash;
            auto txs = state->txs;
            uint64_t seq = ++state->chain.template_seq;
            state->chain.last_template_fee_sum = state->chain.pending_fee_sum;
            return std::make_unique<MockBlockTemplate>(state, prev, std::move(txs), seq, state->chain.pending_fee_sum);
        }
        if (state->events.empty()) continue; // spurious
        MockEvent ev = state->events.front();
        state->events.pop();
        bool emit = false;
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
bool MockMining::isInitialBlockDownload() { return false; }
std::optional<interfaces::BlockRef> MockMining::getTip()
{
    if (state->fail_get_tip) throw std::runtime_error("mock getTip failure");
    return std::nullopt;
}
std::optional<interfaces::BlockRef> MockMining::waitTipChanged(uint256, MillisecondsDouble) { return std::nullopt; }
std::unique_ptr<interfaces::BlockTemplate> MockMining::createNewBlock(const node::BlockCreateOptions& options, bool)
{
    WAIT_LOCK(state->m, lock);
    state->create_weights.push_back(options.block_reserved_weight);
    state->cv.notify_all();
    // Bound the pause so a failing test can't leave fixture teardown waiting forever.
    if (!state->cv.wait_for(lock, std::chrono::seconds{5}, [&]() EXCLUSIVE_LOCKS_REQUIRED(state->m) {
            return state->shutdown || state->mining_interrupted || !state->pause_create;
        })) {
        throw std::runtime_error("createNewBlock pause timed out");
    }
    if (state->shutdown || state->mining_interrupted) return nullptr;
    if (state->max_reserved_weight && options.block_reserved_weight > state->max_reserved_weight) {
        throw std::runtime_error(strprintf("block_reserved_weight (%d) exceeds block_max_weight (%d)",
                                           options.block_reserved_weight, state->max_reserved_weight));
    }
    uint64_t seq = ++state->chain.template_seq;
    return std::make_unique<MockBlockTemplate>(state, state->chain.prev_hash, state->txs, seq, state->chain.pending_fee_sum);
}
void MockMining::interrupt()
{
    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "mock interrupt()");
    LOCK(state->m);
    state->mining_interrupted = true;
    state->cv.notify_all();
}
bool MockMining::checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) { return true; }
std::unique_ptr<interfaces::Block> MockMining::submitBlock(const CBlock& block, bool& accepted, std::string&, std::string&)
{
    accepted = true;
    return std::make_unique<MockBlock>(state, block);
}
bool MockMining::submitBlockOld7(const CBlock&, std::string&, std::string&) { return true; }
std::vector<CTransactionRef> MockMining::getTransactionsByTxID(const std::vector<Txid>& txids)
{
    LOCK(state->m);
    std::vector<CTransactionRef> result;
    for (const Txid& txid : txids) {
        const auto it{std::find_if(state->txs.begin(), state->txs.end(), [&txid](const CTransactionRef& tx) { return tx->GetHash() == txid; })};
        result.push_back(it == state->txs.end() ? nullptr : *it);
    }
    return result;
}
std::vector<CTransactionRef> MockMining::getTransactionsByWitnessID(const std::vector<Wtxid>& wtxids)
{
    LOCK(state->m);
    std::vector<CTransactionRef> result;
    for (const Wtxid& wtxid : wtxids) {
        const auto it{std::find_if(state->txs.begin(), state->txs.end(), [&wtxid](const CTransactionRef& tx) { return tx->GetWitnessHash() == wtxid; })};
        result.push_back(it == state->txs.end() ? nullptr : *it);
    }
    return result;
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

std::vector<uint64_t> MockMining::GetCreateWeights()
{
    LOCK(state->m);
    return state->create_weights;
}

void MockMining::PauseCreate(bool pause)
{
    LOCK(state->m);
    state->pause_create = pause;
    state->cv.notify_all();
}

bool MockMining::WaitForCreateCalls(size_t count, std::chrono::milliseconds timeout)
{
    WAIT_LOCK(state->m, lock);
    return state->cv.wait_for(lock, timeout, [&]() EXCLUSIVE_LOCKS_REQUIRED(state->m) {
        return state->shutdown || state->create_weights.size() >= count;
    }) && !state->shutdown && state->create_weights.size() >= count;
}

void MockMining::FailWaitNext()
{
    LOCK(state->m);
    state->fail_wait_next = true;
    state->cv.notify_all();
}

bool MockMining::WaitForTemplateSeq(uint64_t target, std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&]{ return state->shutdown || state->chain.template_seq >= target; }) && !state->shutdown && state->chain.template_seq >= target;
}

bool MockMining::WaitForWaitNext(int min_waiters, std::chrono::milliseconds timeout)
{
    std::unique_lock<Mutex> lk(state->m);
    auto deadline = std::chrono::steady_clock::now() + timeout;
    return state->cv.wait_until(lk, deadline, [&]{ return state->shutdown || state->wait_next_waiters >= min_waiters; }) && !state->shutdown && state->wait_next_waiters >= min_waiters;
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
    state->chain.height++;
    state->chain.prev_hash = HashFromHeight(state->chain.height);
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
