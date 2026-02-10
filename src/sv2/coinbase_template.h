// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_COINBASE_TEMPLATE_H
#define BITCOIN_SV2_COINBASE_TEMPLATE_H

#include <consensus/amount.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <script/script.h>
#include <primitives/transaction.h>
#include <util/time.h>
#include <vector>

namespace node {

struct CoinbaseTx {
    /* nVersion */
    uint32_t version;
    /* nSequence for the only coinbase transaction input */
    uint32_t sequence;
    /**
     * Prefix which needs to be placed at the beginning of the scriptSig.
     * Clients may append extra data to this as long as the overall scriptSig
     * size is 100 bytes or less, to avoid the block being rejected with
     * "bad-cb-length" error.
     *
     * Currently with BIP 34, the prefix is guaranteed to be less than 8 bytes,
     * but future soft forks could require longer prefixes.
     */
    CScript script_sig_prefix;
    /**
     * The first (and only) witness stack element of the coinbase input.
     *
     * Omitted for block templates without witness data.
     *
     * This is currently the BIP 141 witness reserved value, and can be chosen
     * arbitrarily by the node, but future soft forks may constrain it.
     */
    std::optional<uint256> witness;
    /**
     * Block subsidy plus fees, minus any non-zero required_outputs.
     *
     * Currently there are no non-zero required_outputs, so block_reward_remaining
     * is the entire block reward. See also required_outputs.
     */
    CAmount block_reward_remaining;
    /*
     * To be included as the last outputs in the coinbase transaction.
     * Currently this is only the witness commitment OP_RETURN, but future
     * softforks or a custom mining patch could add more.
     *
     * The dummy output that spends the full reward is excluded.
     */
    std::vector<CTxOut> required_outputs;
    uint32_t lock_time;
};

} // namespace node

#endif // BITCOIN_SV2_COINBASE_TEMPLATE_H
