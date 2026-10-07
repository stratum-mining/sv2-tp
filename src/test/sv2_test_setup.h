// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_TEST_SETUP_H
#define BITCOIN_TEST_SV2_TEST_SETUP_H

#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <key.h>
#include <sv2/messages.h>
#include <sv2/noise.h>
#include <threadsafety.h>
#include <test/util/random.h>
#include <util/fs.h>
#include <util/time.h>

/**
 * Helper to build a skew-tolerant test certificate.
 *
 * Centralizes the decision to backdate valid_from by an hour so that CI
 * environments with slight clock skew or start-up adjustments do not cause
 * flakiness in certificate validation.
 *
 * Returns the constructed Sv2Certificate and populates the timing
 * output parameters for additional negative test cases (future start, expiry, etc.).
 */
inline Sv2Certificate MakeSkewTolerantCertificate(const CKey& static_key,
                                                           const CKey& authority_key,
                                                           uint32_t& out_now,
                                                           uint32_t& out_valid_from,
                                                           uint32_t& out_valid_to,
                                                           uint32_t backdate_secs = 3600,
                                                           uint16_t version = 0)
{
    const auto now = GetTime<std::chrono::seconds>();
    const int64_t now_count = now.count();
    const int64_t clamped_now = std::max<int64_t>(0, now_count);
    out_now = static_cast<uint32_t>(clamped_now);

    const int64_t backdated = std::max<int64_t>(0, clamped_now - static_cast<int64_t>(backdate_secs));
    out_valid_from = static_cast<uint32_t>(backdated);
    out_valid_to = std::numeric_limits<unsigned int>::max();

    return Sv2Certificate(version, out_valid_from, out_valid_to,
                          XOnlyPubKey(static_key.GetPubKey()), authority_key);
}

//! Default mock time for SV2 unit tests: Bitcoin genesis block timestamp (2009-01-03).
inline constexpr std::chrono::seconds TEST_GENESIS_TIME{1231006505};


class ECC_Context;

// Minimal test fixture for SV2 tests that avoids node/chainstate dependencies.
struct Sv2BasicTestingSetup {
    FastRandomContext m_rng;
    std::unique_ptr<ECC_Context> m_ecc;

    Sv2BasicTestingSetup();
    ~Sv2BasicTestingSetup();

private:
    fs::path m_tmp_root;
};

/** A valid SubmitSolution message for template id 2. */
node::Sv2NetMsg TestSubmitSolutionMsg();

/**
 * Coinbase that TestProposeTemplateMsg() splits into prefix and suffix: a
 * segwit coinbase whose scriptSig is a BIP34 height push followed by an all
 * zero 8 byte extranonce.
 */
CMutableTransaction TestProposeTemplateCoinbase();

/** A ProposeTemplate message for TestProposeTemplateCoinbase() and the given wtxids. */
node::Sv2NetMsg TestProposeTemplateMsg(uint32_t request_id, const std::vector<Wtxid>& wtxids);

/** A ProvideMissingTransactions.Success message with the given transactions. */
node::Sv2NetMsg TestProvideMissingTransactionsMsg(uint32_t request_id, const std::vector<CTransactionRef>& transaction_list);

/** Collects log lines while in scope. */
class Sv2LogCapture
{
public:
    Sv2LogCapture();
    ~Sv2LogCapture();

    /** Wait until a captured line contains needle. */
    bool WaitFor(std::string_view needle, std::chrono::milliseconds timeout = std::chrono::milliseconds{2000});

private:
    //! Not a Mutex: the callback runs while the logger holds its own lock,
    //! and LOCK() may itself log on contention.
    StdMutex m_mutex;
    std::vector<std::string> m_lines GUARDED_BY(m_mutex);
    std::list<std::function<void(const std::string&)>>::iterator m_callback;
};

#endif // BITCOIN_TEST_SV2_TEST_SETUP_H
