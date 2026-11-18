// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_MINING_H
#define BITCOIN_INTERFACES_MINING_H

#include <consensus/amount.h>
#include <interfaces/types.h>
#include <sv2/block_options.h>
#include <sv2/coinbase_template.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/time.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace node {
struct NodeContext;
} // namespace node

class BlockValidationState;
class CScript;

namespace interfaces {

//! Handle to a block. Holding it keeps the block available, so clients can
//! fetch its data later, or not at all.
class Block
{
public:
    virtual ~Block() = default;

    //! Return the block header.
    virtual CBlockHeader header() = 0;

    //! Return the full block.
    virtual CBlock data() = 0;

    /**
     * Compute merkle path to the coinbase transaction
     *
     * @return merkle path ordered from the deepest
     */
    virtual std::vector<uint256> coinbaseMerklePath() = 0;
};

//! Block template interface
class BlockTemplate
{
public:
    virtual ~BlockTemplate() = default;

    /**
     * Older version of Block::header() (mining.capnp @1), as used by Bitcoin
     * Core v31 and v32. Nodes that have the newer method throw when this is
     * called.
     */
    virtual CBlockHeader getBlockHeaderOld1() = 0;

    /**
     * Return the template block. It contains a dummy coinbase transaction
     * that should not be used. The template is unchanged by submitSolution().
     *
     * The handle remains valid after the template is destroyed.
     *
     * @note Bitcoin Core v31 and v32 do not have this method (mining.capnp
     *       @11). Use getBlockOld2() there, see
     *       Sv2TemplateProvider::DetectTemplateInterface().
     */
    virtual std::unique_ptr<Block> block() = 0;

    /**
     * Older version of block() (mining.capnp @2), as used by Bitcoin Core v31
     * and v32. It returns the block itself, which submitSolutionOld7() and
     * submitSolutionOld10() modify in place.
     *
     * Nodes that have the newer method throw when this is called.
     */
    virtual CBlock getBlockOld2() = 0;

    // Fees per transaction, not including coinbase transaction.
    virtual std::vector<CAmount> getTxFees() = 0;
    // Sigop cost per transaction, not including coinbase transaction.
    virtual std::vector<int64_t> getTxSigops() = 0;

    /** Return fields needed to construct a coinbase transaction */
    virtual node::CoinbaseTx getCoinbaseTx() = 0;

    /**
     * Older version of Block::coinbaseMerklePath() (mining.capnp @6), as used
     * by Bitcoin Core v31 and v32. Nodes that have the newer method throw when
     * this is called.
     */
    virtual std::vector<uint256> getCoinbaseMerklePathOld6() = 0;

    /**
     * Construct and broadcast a block from a copy of the template,
     * updating the fields listed below as well as the merkle root.
     * The template itself is unchanged.
     *
     * @param[in] version version block header field
     * @param[in] timestamp time block header field (unix timestamp)
     * @param[in] nonce nonce block header field
     * @param[in] coinbase complete coinbase transaction (including witness)
     * @param[out] accepted true if accepted as a new block
     * @param[out] reason failure reason (BIP22)
     * @param[out] debug  more detailed rejection reason
     *
     * @note unlike the submitblock RPC, this method does NOT add the
     *       coinbase witness automatically.
     *
     * @returns a handle to the submitted block, including on rejection
     * @throws std::invalid_argument if coinbase is null
     *
     * @note Bitcoin Core v31 and v32 do not have this method (mining.capnp
     *       @12). Use submitSolutionOld7() or submitSolutionOld10() there, see
     *       Sv2TemplateProvider::DetectNodeVersion() and
     *       Sv2TemplateProvider::DetectTemplateInterface().
     */
    virtual std::unique_ptr<Block> submitSolution(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase, bool& accepted, std::string& reason, std::string& debug) = 0;

    /**
     * Older version of submitSolution() (mining.capnp @10), as used by
     * Bitcoin Core v32. It modifies the template in place and returns true if
     * the block was accepted as a new block.
     *
     * Nodes that have the newer method throw when this is called.
     */
    virtual bool submitSolutionOld10(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase, std::string& reason, std::string& debug) = 0;

    /**
     * Older version of submitSolution() (mining.capnp @7), as used by Bitcoin
     * Core v31. It does not return a reason or debug string, and returns true
     * if the block was processed, which does not necessarily indicate validity
     * or that it was new. It modifies the template in place.
     *
     * Nodes that have a newer method throw when this is called.
     */
    virtual bool submitSolutionOld7(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase) = 0;

    /**
     * Waits for fees in the next block to rise, a new tip or the timeout.
     *
     * @param[in] options   Control the timeout (default forever) and by how much total fees
     *                      for the next block should rise (default infinite).
     *
     * @returns a new BlockTemplate or nothing if the timeout occurs.
     *
     * On testnet this will additionally return a template with difficulty 1 if
     * the tip is more than 20 minutes old.
     */
    virtual std::unique_ptr<BlockTemplate> waitNext(node::BlockWaitOptions options = {}) = 0;

    /**
     * Interrupts the current wait for the next block template.
    */
    virtual void interruptWait() = 0;
};

//! Interface giving clients (RPC, Stratum v2 Template Provider in the future)
//! ability to create block templates.
class Mining
{
public:
    virtual ~Mining() = default;

    //! If this chain is exclusively used for testing
    virtual bool isTestChain() = 0;

    //! Returns whether IBD is still in progress.
    virtual bool isInitialBlockDownload() = 0;

    //! Returns the hash and height for the tip of this chain
    virtual std::optional<BlockRef> getTip() = 0;

    /**
     * Waits for the connected tip to change. During node initialization, this will
     * wait until the tip is connected (regardless of `timeout`).
     *
     * @param[in] current_tip block hash of the current chain tip. Function waits
     *                        for the chain tip to differ from this.
     * @param[in] timeout     how long to wait for a new tip (default is forever)
     *
     * @retval BlockRef hash and height of the current chain tip after this call.
     * @retval std::nullopt if the node is shut down or interrupt() is called.
     */
    virtual std::optional<BlockRef> waitTipChanged(uint256 current_tip, MillisecondsDouble timeout = MillisecondsDouble::max()) = 0;

   /**
     * Construct a new block template.
     *
     * @param[in] options options for creating the block
     * @param[in] cooldown wait for tip to be connected and IBD to complete.
     *                     If the best header is ahead of the tip, wait for the
     *                     tip to catch up. It's recommended to disable this on
     *                     regtest and signets with only one miner, as these
     *                     could stall.
     * @retval BlockTemplate a block template.
     * @retval std::nullptr if the node is shut down or interrupt() is called.
     */
    virtual std::unique_ptr<BlockTemplate> createNewBlock(const node::BlockCreateOptions& options = {}, bool cooldown = true) = 0;

    /**
     * Interrupts createNewBlock and waitTipChanged.
     */
    virtual void interrupt() = 0;

    /**
     * Checks if a given block is valid.
     *
     * @param[in] block       the block to check
     * @param[in] options     verification options: the proof-of-work check can be
     *                        skipped in order to verify a template generated by
     *                        external software.
     * @param[out] reason     failure reason (BIP22)
     * @param[out] debug      more detailed rejection reason
     * @returns               whether the block is valid
     *
     * For signets the challenge verification is skipped when check_pow is false.
     */
    virtual bool checkBlock(const CBlock& block, const node::BlockCheckOptions& options, std::string& reason, std::string& debug) = 0;

    /**
     * Process a fully assembled block.
     *
     * Not used by sv2-tp, but needed to keep the capnp ordinals in sync with
     * Bitcoin Core, see mining.capnp.
     *
     * @param[in]  block  the complete block to submit
     * @param[out] accepted true if the block was accepted as a new block. Set
     *                    to false, with reason set, if the block is a duplicate
     *                    or the validation result is inconclusive.
     * @param[out] reason failure reason (BIP22)
     * @param[out] debug  more detailed rejection reason
     * @returns           a handle to the submitted block, including on rejection
     *
     * @note Unlike the submitblock RPC, this method does not add a missing
     *       coinbase witness reserved value. The block must be complete.
     * @note Bitcoin Core v31 and v32 do not have this method (mining.capnp
     *       @10).
     */
    virtual std::unique_ptr<Block> submitBlock(const CBlock& block, bool& accepted, std::string& reason, std::string& debug) = 0;

    /**
     * Older version of submitBlock() (mining.capnp @7), as used by Bitcoin
     * Core v32. Not used by sv2-tp.
     *
     * @note Bitcoin Core v31 does not have this method and throws when it is
     *       called, see Sv2TemplateProvider::DetectNodeVersion(). Nodes that
     *       have the newer method throw as well.
     */
    virtual bool submitBlockOld7(const CBlock& block, std::string& reason, std::string& debug) = 0;

    /**
     * Fetch raw transactions from the mempool by txid.
     *
     * sv2-tp only uses this to detect the version of the node's mining
     * interface, see Sv2TemplateProvider::DetectNodeVersion().
     *
     * @param[in] txids   transaction ids to look up
     * @returns           one entry per requested txid containing the
     *                    transaction if found, otherwise nullptr
     */
    virtual std::vector<CTransactionRef> getTransactionsByTxID(const std::vector<Txid>& txids) = 0;

    /**
     * Fetch raw transactions from the mempool by wtxid.
     *
     * Not used by sv2-tp, but needed to keep the Mining interface in sync
     * with Bitcoin Core v32, see mining.capnp.
     *
     * @param[in] wtxids  witness transaction ids to look up
     * @returns           one entry per requested wtxid containing the
     *                    transaction if found, otherwise nullptr
     *
     * @note Bitcoin Core v31 does not have this method, see submitBlockOld7().
     */
    virtual std::vector<CTransactionRef> getTransactionsByWitnessID(const std::vector<Wtxid>& wtxids) = 0;

    //! Get internal node context. Useful for RPC and testing,
    //! but not accessible across processes.
    virtual node::NodeContext* context() { return nullptr; }
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_MINING_H
