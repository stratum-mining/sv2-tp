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

node::Sv2SetNewPrevHashMsg::Sv2SetNewPrevHashMsg(const CBlockHeader& header, uint64_t template_id) : m_template_id{template_id}
{
    m_prev_hash = header.hashPrevBlock;
    m_header_timestamp = header.nTime;
    m_nBits = header.nBits;
    m_target = ArithToUint256(arith_uint256().SetCompact(header.nBits));
}
