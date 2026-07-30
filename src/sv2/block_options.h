// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_BLOCK_OPTIONS_H
#define BITCOIN_SV2_BLOCK_OPTIONS_H

#include <consensus/amount.h>
#include <cstddef>
#include <cstdint>
#include <util/time.h>

namespace node {

//! Default reserved weight for block assembly scaffolding (header, coinbase, etc).
inline constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
//! Minimum reserved weight enforced by block assembly.
inline constexpr size_t MIN_BLOCK_RESERVED_WEIGHT{2000};

//! Weight to reserve for a client's coinbase outputs of up to
//! max_additional_size bytes. Computed in 64 bits, so it can't overflow for
//! any 32-bit size a client sends.
constexpr uint64_t ReservedWeightForCoinbaseOutputs(uint64_t max_additional_size)
{
    // https://stratumprotocol.org/specification/07-Template-Distribution-Protocol#72-coinbaseoutputconstraints-client-server
    // Weight units reserved for block header, transaction count,
    // and various fixed and variable coinbase fields.
    const uint64_t block_reserved_floor{1168};
    // Reserve a little more so that if the above calculation is
    // wrong or there's an implementation error, we don't produce
    // an invalid block when the template is completely full.
    const uint64_t block_reserved_padding{400};

    return block_reserved_floor + block_reserved_padding + max_additional_size * 4;
}

struct BlockCreateOptions {
    /** Set false to omit mempool transactions from templates. */
    bool use_mempool{true};
    /** Reserved weight for fixed block header + coinbase scaffolding. */
    size_t block_reserved_weight{DEFAULT_BLOCK_RESERVED_WEIGHT};
    /** Maximum additional sigops allowed in downstream coinbase outputs. */
    size_t coinbase_output_max_additional_sigops{400};
};

struct BlockWaitOptions {
    /** Timeout before returning nullptr instead of a new template (default forever). */
    MillisecondsDouble timeout{MillisecondsDouble::max()};
    /** Required fee delta (sat) compared to previous template before returning. */
    CAmount fee_threshold{MAX_MONEY};
};

struct BlockCheckOptions {
    bool check_merkle_root{true};
    bool check_pow{true};
};

} // namespace node

#endif // BITCOIN_SV2_BLOCK_OPTIONS_H
