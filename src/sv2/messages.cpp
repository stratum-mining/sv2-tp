#include <sv2/messages.h>

#include <arith_uint256.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <consensus/validation.h> // NO_WITNESS_COMMITMENT
#include <script/script.h>

node::Sv2NewTemplateMsg::Sv2NewTemplateMsg(const CBlockHeader& header, const CTransactionRef coinbase_tx, std::vector<uint256> coinbase_merkle_path, uint64_t template_id, bool future_template)
    : m_template_id{template_id}, m_future_template{future_template}
{
    m_version = header.nVersion;

    m_coinbase_tx_version = coinbase_tx->CURRENT_VERSION;
    m_coinbase_prefix = coinbase_tx->vin[0].scriptSig;
    if (coinbase_tx->HasWitness()) {
        const auto& witness_stack{coinbase_tx->vin[0].scriptWitness.stack};
        Assert(witness_stack.size() == 1 || witness_stack[0].size() == 32);
        m_coinbase_witness = uint256(witness_stack[0]);
    } else {
        m_coinbase_witness = uint256(0);
    }
    m_coinbase_tx_input_sequence = coinbase_tx->vin[0].nSequence;

    // The coinbase nValue already contains the nFee + the Block Subsidy when built using CreateBlock().
    m_coinbase_tx_value_remaining = static_cast<uint64_t>(coinbase_tx->vout[0].nValue);

    // Extract only OP_RETURN coinbase outputs (witness commitment, merge mining, etc.)
    // Bitcoin Core adds a dummy output with the full reward that we must exclude,
    // otherwise the pool would create an invalid block trying to spend that amount again.
    m_coinbase_tx_outputs.clear();
    for (const auto& output : coinbase_tx->vout) {
        if (!output.scriptPubKey.empty() && output.scriptPubKey[0] == OP_RETURN) {
            m_coinbase_tx_outputs.push_back(output);
        }
    }
    m_coinbase_tx_outputs_count = m_coinbase_tx_outputs.size();

    m_coinbase_tx_locktime = coinbase_tx->nLockTime;

    for (const auto& hash : coinbase_merkle_path) {
        m_merkle_path.push_back(hash);
    }

}

node::Sv2SetNewPrevHashMsg::Sv2SetNewPrevHashMsg(const CBlockHeader& header, uint64_t template_id) : m_template_id{template_id}
{
    m_prev_hash = header.hashPrevBlock;
    m_header_timestamp = header.nTime;
    m_nBits = header.nBits;
    m_target = ArithToUint256(arith_uint256().SetCompact(header.nBits));
}
