// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_COINBASE_TEMPLATE_H
#define BITCOIN_SV2_COINBASE_TEMPLATE_H

#include <consensus/amount.h>
#include <cstddef>
#include <cstdint>
#include <script/script.h>
#include <primitives/transaction.h>
#include <util/time.h>
#include <vector>

namespace node {

struct CoinbaseTemplate {
    /* nVersion */
    uint32_t version;
    /* nSequence for the only coinbase transaction input */
    uint32_t sequence;
    /**
     * Bytes which are to be placed at the beginning of scriptSig. Guaranteed
     * to be less than 8 bytes (not including the length byte). This allows
     * clients to add up to 92 bytes.
     */
    CScript script_sig_prefix;
    /**
     * The first (and only) witness stack element of the coinbase input.
     *
     * Omitted for block templates without witness data.
     *
     * This is currently the BIP 141 witness reserved value. A future soft fork
     * may move the witness reserved value elsewhere, but there will still be a
     * coinbase witness.
     */
    std::optional<uint256> witness;
    /**
     * Block subsidy plus fees, minus any non-zero required_outputs.
     *
     * Currently there are no non-zero required_outputs, see below.
     */
    CAmount value_remaining;
    /*
     * To be included as the last outputs in the coinbase transaction.
     * Currently this is only the witness commitment OP_RETURN, but future
     * softforks could add more.
     * If a patch to BlockAssembler::CreateNewBlock() adds outputs e.g. for
     * merge mining, those will be included. The dummy output that spends
     * the full reward is excluded.
     */
    std::vector<CTxOut> required_outputs;
    uint32_t lock_time;
};

} // namespace node

#endif // BITCOIN_SV2_COINBASE_TEMPLATE_H
