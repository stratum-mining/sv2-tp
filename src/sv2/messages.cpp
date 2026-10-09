#include <sv2/messages.h>

#include <arith_uint256.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <consensus/validation.h> // NO_WITNESS_COMMITMENT
#include <script/script.h>

node::Sv2NewTemplateMsg::Sv2NewTemplateMsg(const CBlockHeader& header, const node::CoinbaseTx coinbase, std::vector<uint256> coinbase_merkle_path, uint64_t template_id, bool future_template)
    : m_template_id{template_id}, m_future_template{future_template}
{
    m_version = header.nVersion;

    m_coinbase_tx_version = coinbase.version;
    m_coinbase_prefix = coinbase.script_sig_prefix;
    m_coinbase_tx_input_sequence = coinbase.sequence;

    // The coinbase nValue already contains the nFee + the Block Subsidy when built using CreateBlock().
    m_coinbase_tx_value_remaining = static_cast<uint64_t>(coinbase.block_reward_remaining);

    // Extract only OP_RETURN coinbase outputs (witness commitment, merge mining, etc.)
    // Bitcoin Core adds a dummy output with the full reward that we must exclude,
    // otherwise the pool would create an invalid block trying to spend that amount again.
    m_coinbase_tx_outputs.clear();
    for (const auto& output : coinbase.required_outputs) {
        m_coinbase_tx_outputs.push_back(output);
    }
    m_coinbase_tx_outputs_count = coinbase.required_outputs.size();

    m_coinbase_tx_locktime = coinbase.lock_time;

    for (const auto& hash : coinbase_merkle_path) {
        m_merkle_path.push_back(hash);
    }

}

node::CoinbaseTx ExtractCoinbaseTx(const CTransactionRef coinbase_tx)
{
    node::CoinbaseTx coinbase{};

    coinbase.version = coinbase_tx->version;
    Assert(coinbase_tx->vin.size() == 1);
    coinbase.script_sig_prefix = coinbase_tx->vin[0].scriptSig;
    // The CoinbaseTx interface guarantees a size limit. Raising it (e.g.
    // if a future softfork needs to commit more than BIP34) is a
    // (potentially silent) breaking change for clients.
    if (!Assume(coinbase.script_sig_prefix.size() <= 8)) {
        LogWarning("Unexpected %d byte scriptSig prefix size.",
                    coinbase.script_sig_prefix.size());
    }

    if (coinbase_tx->HasWitness()) {
        const auto& witness_stack{coinbase_tx->vin[0].scriptWitness.stack};
        // Consensus requires the coinbase witness stack to have exactly one
        // element of 32 bytes.
        Assert(witness_stack.size() == 1 && witness_stack[0].size() == 32);
        coinbase.witness = uint256(witness_stack[0]);
    }

    coinbase.sequence = coinbase_tx->vin[0].nSequence;

    // Extract only OP_RETURN coinbase outputs (witness commitment, merge
    // mining, etc). BlockAssembler::CreateNewBlock adds a dummy output with
    // the full reward that we must exclude.
    for (const auto& output : coinbase_tx->vout) {
        if (!output.scriptPubKey.empty() && output.scriptPubKey[0] == OP_RETURN) {
            coinbase.required_outputs.push_back(output);
        } else {
            // The (single) dummy coinbase output produced by CreateBlock() has
            // an nValue set to nFee + the Block Subsidy.
            Assume(coinbase.block_reward_remaining == 0);
            coinbase.block_reward_remaining = output.nValue;
        }
    }

    coinbase.lock_time = coinbase_tx->nLockTime;

    return coinbase;
}

node::Sv2NewTemplateMsg::Sv2NewTemplateMsg(const CBlockHeader& header, const CTransactionRef coinbase_tx, std::vector<uint256> coinbase_merkle_path, uint64_t template_id, bool future_template) :
    node::Sv2NewTemplateMsg(header, ExtractCoinbaseTx(coinbase_tx), coinbase_merkle_path, template_id, future_template) {};

CMutableTransaction node::Sv2ProposeTemplateMsg::Coinbase() const
{
    // The prefix holds nVersion, the BIP144 marker and flag for a segwit
    // coinbase, the input count, the null prevout, the scriptSig length and
    // the part of the scriptSig before the extranonce.
    DataStream prefix{m_coinbase_tx_prefix};
    prefix.ignore(4);
    if (prefix.size() >= 2 && prefix[0] == std::byte{0x00} && prefix[1] == std::byte{0x01}) prefix.ignore(2);
    if (ReadCompactSize(prefix) != 1) throw std::ios_base::failure("coinbase must have one input");
    prefix.ignore(32 + 4);
    const uint64_t script_sig_len{ReadCompactSize(prefix)};
    // Consensus limits the coinbase scriptSig to 2 through 100 bytes
    // (bad-cb-length). Refusing anything larger also bounds the allocation below.
    if (script_sig_len < 2 || script_sig_len > 100) throw std::ios_base::failure("coinbase scriptSig length out of range");
    if (prefix.size() > script_sig_len) throw std::ios_base::failure("prefix holds more scriptSig bytes than its length");
    const size_t extranonce_len{script_sig_len - prefix.size()};

    std::vector<uint8_t> raw{m_coinbase_tx_prefix};
    raw.resize(raw.size() + extranonce_len, 0);
    raw.insert(raw.end(), m_coinbase_tx_suffix.begin(), m_coinbase_tx_suffix.end());

    DataStream ss{raw};
    CMutableTransaction coinbase;
    ss >> TX_WITH_WITNESS(coinbase);
    if (!ss.empty()) throw std::ios_base::failure("bytes after the coinbase");
    return coinbase;
}

node::Sv2SetNewPrevHashMsg::Sv2SetNewPrevHashMsg(const CBlockHeader& header, uint64_t template_id) : m_template_id{template_id}
{
    m_prev_hash = header.hashPrevBlock;
    m_ntime_start = header.nTime;
    m_nBits = header.nBits;
    m_target = ArithToUint256(arith_uint256().SetCompact(header.nBits));
}
