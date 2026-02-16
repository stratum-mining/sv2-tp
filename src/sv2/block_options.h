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
static constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
//! Minimum reserved weight enforced by block assembly.
static constexpr size_t MIN_BLOCK_RESERVED_WEIGHT{2000};

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
