#include <cstdint>
#include <memory>
#include <sv2/template_provider.h>

#include <base58.h>
#include <consensus/merkle.h>
#include <crypto/hex_base.h>
#include <common/args.h>
#include <ipc/exception.h>
#include <logging.h>
#include <sv2/noise.h>
#include <consensus/validation.h> // NO_WITNESS_COMMITMENT
#include <util/chaintype.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <streams.h>
#include <sync.h>

#include <consensus/consensus.h>

#include <algorithm>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>

// Allow a few seconds for clients to submit a block or to request transactions
constexpr size_t STALE_TEMPLATE_GRACE_PERIOD{10};

namespace {
/**
 * A block that a client proposed and the node accepted in checkBlock(). It
 * lives in the template cache next to the node's own templates, so
 * SubmitSolution, RequestTransactionData and cache pruning need no special
 * case. A solution is broadcast through Mining::submitBlock().
 *
 * Bitcoin Core PR #35671 (TxCollection::makeTemplate()) would return a
 * node-side equivalent of this object.
 */
class ProposedBlockTemplate : public BlockTemplate
{
public:
    ProposedBlockTemplate(interfaces::Mining& mining, CBlock block) : m_mining{mining}, m_block{std::move(block)} {}

    CBlockHeader getBlockHeader() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) { return WITH_LOCK(m_mutex, return m_block.GetBlockHeader()); }
    CBlock getBlock() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) { return WITH_LOCK(m_mutex, return m_block); }

    // The node validated the block, but told us nothing else about it.
    std::vector<CAmount> getTxFees() override { throw std::logic_error("getTxFees() is not available for a proposed template"); }
    std::vector<int64_t> getTxSigops() override { throw std::logic_error("getTxSigops() is not available for a proposed template"); }
    node::CoinbaseTx getCoinbaseTx() override { throw std::logic_error("getCoinbaseTx() is not available for a proposed template"); }
    std::vector<uint256> getCoinbaseMerklePath() override { throw std::logic_error("getCoinbaseMerklePath() is not available for a proposed template"); }
    std::unique_ptr<BlockTemplate> waitNext(node::BlockWaitOptions) override { throw std::logic_error("waitNext() is not available for a proposed template"); }
    // Sv2TemplateProvider::Interrupt() calls this on every cached template.
    void interruptWait() override {}

    bool submitSolution(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase, std::string& reason, std::string& debug) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        CBlock block;
        {
            LOCK(m_mutex);
            m_block.nVersion = static_cast<int32_t>(version);
            m_block.nTime = timestamp;
            m_block.nNonce = nonce;
            m_block.vtx[0] = std::move(coinbase);
            m_block.hashMerkleRoot = BlockMerkleRoot(m_block);
            block = m_block;
        }
        return m_mining.submitBlock(block, reason, debug);
    }

    bool submitSolutionOld7(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::string reason, debug;
        return submitSolution(version, timestamp, nonce, std::move(coinbase), reason, debug);
    }

private:
    interfaces::Mining& m_mining;
    Mutex m_mutex;
    CBlock m_block GUARDED_BY(m_mutex);
};
} // namespace

Sv2TemplateProvider::Sv2TemplateProvider(interfaces::Mining& mining) : m_mining{mining}
{
    // TODO: persist static key
    CKey static_key;
    try {
        AutoFile{fsbridge::fopen(GetStaticKeyFile(), "rb")} >> static_key;
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Reading cached static key from %s\n", fs::PathToString(GetStaticKeyFile()));
    } catch (const std::ios_base::failure&) {
        // File is not expected to exist the first time.
        // In the unlikely event that loading an existing key fails, create a new one.
    }
    if (!static_key.IsValid()) {
        static_key = GenerateRandomKey();
        try {
            AutoFile static_key_file{fsbridge::fopen(GetStaticKeyFile(), "wb")};
            static_key_file << static_key;
            // Ignore failure to close
            (void)static_key_file.fclose();
        } catch (const std::ios_base::failure&) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Error writing static key to %s\n", fs::PathToString(GetStaticKeyFile()));
            // Continue, because this is not a critical failure.
        }
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Generated static key, saved to %s\n", fs::PathToString(GetStaticKeyFile()));
    }
    LogPrintLevel(BCLog::SV2, BCLog::Level::Info, "Static key: %s\n", HexStr(static_key.GetPubKey()));

    // Generate a certificate for the static key, signed by the authority key.
    // TODO: skip loading authoritity key if -sv2cert is used

    // Load authority key if cached
    CKey authority_key;
    try {
        AutoFile{fsbridge::fopen(GetAuthorityKeyFile(), "rb")} >> authority_key;
    } catch (const std::ios_base::failure&) {
        // File is not expected to exist the first time.
        // In the unlikely event that loading an existing key fails, create a new one.
    }
    if (!authority_key.IsValid()) {
        authority_key = GenerateRandomKey();
        try {
            AutoFile authority_key_file{fsbridge::fopen(GetAuthorityKeyFile(), "wb")};
            authority_key_file << authority_key;
            // Ignore failure to close
            (void)authority_key_file.fclose();
        } catch (const std::ios_base::failure&) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Error writing authority key to %s\n", fs::PathToString(GetAuthorityKeyFile()));
            // Continue, because this is not a critical failure.
        }
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Generated authority key, saved to %s\n", fs::PathToString(GetAuthorityKeyFile()));
    }
    // SRI uses base58 encoded x-only pubkeys in its configuration files
    std::array<unsigned char, 34> version_pubkey_bytes;
    version_pubkey_bytes[0] = 1;
    version_pubkey_bytes[1] = 0;
    m_authority_pubkey = XOnlyPubKey(authority_key.GetPubKey());
    std::copy(m_authority_pubkey.begin(), m_authority_pubkey.end(), version_pubkey_bytes.begin() + 2);
    LogPrintLevel(BCLog::SV2, BCLog::Level::Info, "Template Provider authority key: %s\n", EncodeBase58Check(version_pubkey_bytes));
    LogTrace(BCLog::SV2, "Authority key: %s\n", HexStr(m_authority_pubkey));

    // Generate and sign certificate
    const int64_t now_seconds{std::max<int64_t>(GetTime<std::chrono::seconds>().count(), 0)};
    // Start validity a little bit in the past to account for clock difference
    const int64_t backdated{std::max<int64_t>(now_seconds - int64_t{3600}, 0)};
    const uint32_t valid_from{static_cast<uint32_t>(std::min<int64_t>(backdated, std::numeric_limits<uint32_t>::max()))};
    const uint32_t valid_to{std::numeric_limits<uint32_t>::max()}; // 2106
    uint16_t version = 0;
    Sv2Certificate certificate = Sv2Certificate(version, valid_from, valid_to, XOnlyPubKey(static_key.GetPubKey()), authority_key);

    m_connman = std::make_unique<Sv2Connman>(static_key, m_authority_pubkey, certificate);
}

fs::path Sv2TemplateProvider::GetStaticKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_static_key";
}

fs::path Sv2TemplateProvider::GetAuthorityKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_authority_key";
}

void Sv2TemplateProvider::DetectNodeVersion()
{
    // getTransactionsByTxID() was added to the Mining interface after Bitcoin
    // Core v31. Calling it with an empty list has no side effects, and lets us
    // find out which interface the node has before we need to know.
    try {
        m_mining.getTransactionsByTxID({});
        m_node_version = NODE_VERSION_32_00;
    } catch (const ipc::Exception& e) {
        // ipc::Exception does not preserve the Cap'n Proto error type, so
        // match its missing-method diagnostic. Other failures must propagate.
        if (std::string_view{e.what()}.find("Method not implemented.") == std::string_view::npos) throw;
        m_node_version = NODE_VERSION_31_0;
        LogTrace(BCLog::SV2, "getTransactionsByTxID() is not available: %s\n", e.what());
        // The IPC layer logs the failed call above as an error, so explain it.
        LogInfo("The IPC error above is expected when connecting to Bitcoin Core v31, which "
                "has an older mining interface\n");
    }
}

bool Sv2TemplateProvider::Start(const Sv2TemplateProviderOptions& options)
{
    m_options = options;

    DetectNodeVersion();

    // ProposeTemplate needs getTransactionsByWitnessID() and submitBlock(),
    // which Bitcoin Core v31 does not have.
    const uint32_t supported_flags{m_node_version >= NODE_VERSION_32_00 ? node::REQUIRES_JOB_VALIDATION : 0};
    if (!m_connman->Start(this, m_options.host, m_options.port, supported_flags)) {
        return false;
    }

    m_thread_sv2_handler = std::thread(&util::TraceThread, "sv2", [this] { ThreadSv2Handler(); });
    if (supported_flags & node::REQUIRES_JOB_VALIDATION) {
        m_thread_sv2_proposal_handler = std::thread(&util::TraceThread, "sv2-propose", [this] { ThreadSv2ProposalHandler(); });
    }
    return true;
}

Sv2TemplateProvider::~Sv2TemplateProvider()
{
    AssertLockNotHeld(m_tp_mutex);

    m_connman->Interrupt();
    m_connman->StopThreads();

    Interrupt();
    StopThreads();
}

void Sv2TemplateProvider::BackendDisconnected()
{
    m_backend_connected = false;
    Interrupt();
}

void Sv2TemplateProvider::Interrupt()
{
    AssertLockNotHeld(m_tp_mutex);

    if (m_flag_interrupt_sv2.exchange(true)) return;

    if (m_backend_connected) {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Interrupt pending mining waits...");
        try {
            LOCK(m_tp_mutex);
            for (auto& t : GetBlockTemplates()) {
                t.second.second->interruptWait();
            }
        } catch (const ipc::Exception& e) {
            LogPrintf("Unable to interrupt block-template wait: %s\n", e.what());
            m_backend_connected = false;
        }
    }

    // interruptWait() may be the first call to discover a backend disconnect.
    if (m_backend_connected) {
        try {
            m_mining.interrupt();
        } catch (const ipc::Exception& e) {
            LogPrintf("Unable to interrupt mining IPC: %s\n", e.what());
        }
    }

    // Also interrupt network threads so client handlers can wind down quickly.
    if (m_connman) m_connman->Interrupt();
}

void Sv2TemplateProvider::StopThreads()
{
    if (m_thread_sv2_handler.joinable()) {
        m_thread_sv2_handler.join();
    }
    if (m_thread_sv2_proposal_handler.joinable()) {
        m_thread_sv2_proposal_handler.join();
    }
}

class Timer {
private:
    std::chrono::seconds m_interval;
    std::chrono::seconds m_last_triggered;

public:
    Timer(std::chrono::seconds interval) : m_interval(interval) {
        reset();
    }

    bool trigger() {
        auto now{GetTime<std::chrono::seconds>()};
        if (now - m_last_triggered >= m_interval) {
            m_last_triggered = now;
            return true;
        }
        return false;
    }

    void reset() {
        auto now{GetTime<std::chrono::seconds>()};
        m_last_triggered = now;
    }
};

void Sv2TemplateProvider::ThreadSv2Handler()
{
    // Make sure it's initialized, doesn't need to be accurate.
    {
        LOCK(m_tp_mutex);
        m_last_block_time = GetTime<std::chrono::seconds>();
    }

    // Wait to come out of IBD, except on signet, where we might be the only miner.
    size_t log_ibd{0};
    while (!m_flag_interrupt_sv2 && gArgs.GetChainType() != ChainType::SIGNET) {
        // TODO: Wait until there's no headers-only branch with more work than our chaintip.
        //       The current check can still cause us to broadcast a few dozen useless templates
        //       at startup.
        try {
            if (!m_mining.isInitialBlockDownload()) break;
        } catch (const ipc::Exception& e) {
            LogPrintf("Unable to check initial block download %s\n", e.what());
            return;
        }
        if (log_ibd == 0) {
            LogPrintf("Waiting for IBD to complete on %s network before serving templates (this may take a while)\n",
                      ChainTypeToString(gArgs.GetChainType()));
        } else if (log_ibd % 10 == 0) {
            LogPrintf(".\n");
        }
        log_ibd++;
        std::this_thread::sleep_for(1000ms);
    }

    std::map<size_t, std::thread> client_threads;

    while (!m_flag_interrupt_sv2) {
        // We start with one template per client, which has an interface through
        // which we monitor for better templates.

        m_connman->ForEachClient([this, &client_threads](Sv2Client& client) EXCLUSIVE_LOCKS_REQUIRED(client.cs_status) {
            /**
             * The initial handshake is handled on the Sv2Connman thread. This
             * consists of the noise protocol handshake and the initial Stratum
             * v2 messages SetupConnection and CoinbaseOutputConstraints.
             *
             * A further refactor should make that part non-blocking. But for
             * now we spin up a thread here.
             */
            if (!client.m_coinbase_output_constraints_recv) return;

            if (client_threads.contains(client.m_id)) return;

            client_threads.emplace(client.m_id,
                                   std::thread(&util::TraceThread,
                                               strprintf("sv2-%zu", client.m_id),
                                               [this, &client] { ThreadSv2ClientHandler(client.m_id); }));
        });

        // Take a break (handling new connections is not urgent)
        std::this_thread::sleep_for(100ms);

        LOCK(m_tp_mutex);
        PruneBlockTemplateCache();
    }

    for (auto& thread : client_threads) {
        if (thread.second.joinable()) {
            // If the node is shutting down, then all pending waitNext() calls
            // should return in under a second.
            thread.second.join();
        }
    }


}

void Sv2TemplateProvider::ThreadSv2ClientHandler(size_t client_id)
{
    // A client without a handler thread never receives templates again, so
    // disconnect it when this thread gives up.
    const auto disconnect_client = [this, client_id] {
        LOCK(m_connman->m_clients_mutex);
        if (std::shared_ptr<Sv2Client> client = m_connman->GetClientById(client_id)) {
            LOCK(client->cs_status);
            client->m_disconnect_flag = true;
        }
    };

    try {
        Timer timer(m_options.template_interval);

        const auto prepare_block_create_options = [this, client_id](node::BlockCreateOptions& options, uint64_t& constraints_generation) -> bool {
            {
                LOCK(m_connman->m_clients_mutex);
                std::shared_ptr client = m_connman->GetClientById(client_id);
                if (!client) return false;
                LOCK(client->cs_status);

                // Bitcoin Core enforces a minimum block reserved weight of 2000.
                // Connman limits the size, so the weight fits in size_t.
                options.block_reserved_weight = static_cast<size_t>(std::max<uint64_t>(
                    node::MIN_BLOCK_RESERVED_WEIGHT,
                    node::ReservedWeightForCoinbaseOutputs(client->m_coinbase_tx_outputs_size)));
                // Snapshot the generation with the size, before the IPC call.
                constraints_generation = client->m_coinbase_constraints_generation.load();
            }
            return true;
        };

        std::shared_ptr<BlockTemplate> block_template;
        // Cache most recent block_template->getBlockHeader().hashPrevBlock result.
        uint256 prev_hash;

        // Track the coinbase constraints generation that was active when block_template was built.
        uint64_t constraints_generation_at_build = 0;
        while (!m_flag_interrupt_sv2) {
            if (!block_template) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "%s block template for client id=%zu\n", constraints_generation_at_build == 0 ? "Generate initial" : "Regenerate", client_id);

                // Create block template and store interface reference
                uint64_t template_id;
                {
                    LOCK(m_tp_mutex);
                    template_id = ++m_template_id;
                }

                node::BlockCreateOptions block_create_options{.use_mempool = true};
                if (!prepare_block_create_options(block_create_options, constraints_generation_at_build)) break;

                const auto time_start{SteadyClock::now()};
                try {
                    block_template = m_mining.createNewBlock(block_create_options);
                } catch (const std::exception& e) {
                    // Bitcoin Core v32 rejects out-of-range options instead of
                    // clamping them, e.g. a reserved weight above the node's
                    // -blockmaxweight. A lost node connection also ends up here.
                    // Break rather than rethrow, so the failure is logged once.
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Error, "Could not create a template for client id=%zu, disconnecting: %s\n",
                                  client_id, e.what());
                    disconnect_client();
                    break;
                }
                if (!block_template) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "No new template for client id=%zu, node is shutting down\n",
                        client_id);
                    break;
                }

                bool stale{false};
                {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;
                    LOCK(client->cs_status);
                    // New constraints may have been processed since we requested this template.
                    stale = client->m_coinbase_constraints_generation.load() != constraints_generation_at_build;
                    if (!stale) client->m_current_block_template = block_template;
                }
                if (stale) {
                    // Releasing the template can make an IPC call; drop the locks first.
                    block_template.reset();
                    continue;
                }

                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Assemble template: %.2fms\n",
                    Ticks<MillisecondsDouble>(SteadyClock::now() - time_start));

                prev_hash = block_template->getBlockHeader().hashPrevBlock;
                {
                    LOCK(m_tp_mutex);
                    if (prev_hash != m_best_prev_hash) {
                        m_best_prev_hash = prev_hash;
                        // Does not need to be accurate
                        m_last_block_time = GetTime<std::chrono::seconds>();
                    }

                    // Add template to cache before sending it, to prevent race
                    // condition: https://github.com/stratum-mining/stratum/issues/1773
                    m_block_template_cache.insert({template_id,std::make_pair(prev_hash, block_template)});
                }

                {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;

                    if (client->m_coinbase_constraints_generation.load() != constraints_generation_at_build) {
                        block_template = nullptr;
                        continue;
                    }
                    if (!SendWork(*client, template_id, *block_template, /*future_template=*/true)) {
                        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                    client_id);
                        LOCK(client->cs_status);
                        client->m_disconnect_flag = true;
                    }
                }

                timer.reset();
            }

            // The future template flag is set when there's a new prevhash,
            // not when there's only a fee increase.
            bool future_template{false};

            // -templateinterval=N suppresses fee-based template updates
            // for N seconds after each template. waitNext() is called with
            // fee_threshold=MAX_MONEY (ignoring fee changes) until the timer
            // fires, then with the real fee_delta on the next iteration.
            const bool check_fees{m_options.is_test || timer.trigger()};

            CAmount fee_delta{check_fees ? m_options.fee_delta : MAX_MONEY};

            node::BlockWaitOptions options;
            options.fee_threshold = fee_delta;
            options.timeout = m_options.is_test ? MillisecondsDouble(1000) : m_options.template_interval;
            if (!check_fees) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                              "Ignore fee changes for %d seconds (-templateinterval), wait for a new tip, client id=%zu\n",
                              m_options.template_interval.count(), client_id);
            } else {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                              "Wait up to %d seconds for fees to rise by %lld sat or a new tip, client id=%zu\n",
                              m_options.template_interval.count(),
                              static_cast<long long>(fee_delta),
                              client_id);
            }

            std::shared_ptr<BlockTemplate> tmpl = block_template->waitNext(options);
            // The client may have disconnected during the wait, check now to avoid
            // a spurious IPC call and confusing log statements.
            {
                LOCK(m_connman->m_clients_mutex);
                if (std::shared_ptr<Sv2Client> client = m_connman->GetClientById(client_id)) {
                    if (client->m_coinbase_constraints_generation.load() != constraints_generation_at_build) {
                        block_template = nullptr;
                        continue;
                    }
                } else break;
            }

            // After timeout and during node shutdown this is expect to not be set
            if (tmpl) {
                block_template = tmpl;
                uint256 new_prev_hash{block_template->getBlockHeader().hashPrevBlock};

                // Compare against the handler-local prev_hash, not the shared
                // m_best_prev_hash: another client handler may have already
                // updated the latter for the same tip, but this client still
                // needs its own SetNewPrevHash message.
                if (new_prev_hash != prev_hash) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Tip changed, client id=%zu\n",
                        client_id);
                    future_template = true;
                    prev_hash = new_prev_hash;
                }

                uint64_t template_id;
                {
                    LOCK(m_tp_mutex);
                    // m_best_prev_hash only tracks the best tip for template
                    // cache pruning, not per-client delivery state.
                    if (new_prev_hash != m_best_prev_hash) {
                        m_best_prev_hash = new_prev_hash;
                        // Does not need to be accurate
                        m_last_block_time = GetTime<std::chrono::seconds>();
                    }

                    // Keep this handler's ID: another client may allocate one
                    // before we acquire m_clients_mutex to send the template.
                    template_id = ++m_template_id;

                    // Add template to cache before sending it, to prevent race
                    // condition: https://github.com/stratum-mining/stratum/issues/1773
                    m_block_template_cache.insert({template_id, std::make_pair(new_prev_hash,block_template)});
                }

                {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;

                    {
                        LOCK(client->cs_status);
                        client->m_current_block_template = block_template;
                    }

                    if (client->m_coinbase_constraints_generation.load() != constraints_generation_at_build) {
                        block_template = nullptr;
                        continue;
                    }

                    if (!SendWork(*client, template_id, *block_template, future_template)) {
                        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                    client_id);
                        LOCK(client->cs_status);
                        client->m_disconnect_flag = true;
                    }
                }

                timer.reset();
            }

            if (m_options.is_test) {
                // Take a break
                std::this_thread::sleep_for(50ms);
            }
        }

        {
            LOCK(m_connman->m_clients_mutex);
            if (std::shared_ptr client = m_connman->GetClientById(client_id)) {
                LOCK(client->cs_status);
                client->m_current_block_template =nullptr;
            }
        }
    } catch (const std::exception& e) {
        // Usually the node connection was lost, which the main thread notices
        // and handles, so log at Debug only.
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug,
                      "Client thread for id=%zu exiting after exception, disconnecting: %s\n",
                      client_id, e.what());
        disconnect_client();
    }
}

void Sv2TemplateProvider::RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg)
{
    CBlock block;
    {
        LOCK(m_tp_mutex);
        auto cached_block = m_block_template_cache.find(msg.m_template_id);
        if (cached_block == m_block_template_cache.end()) {
            node::Sv2RequestTransactionDataErrorMsg request_tx_data_error{msg.m_template_id, "template-id-not-found"};

            LogDebug(BCLog::SV2, "Send 0x75 RequestTransactionData.Error (template-id-not-found: %zu) to client id=%zu\n",
                    msg.m_template_id, client.m_id);
            LOCK(client.cs_send);
            client.m_send_messages.emplace_back(request_tx_data_error);

            return;
        }
        block = (*cached_block->second.second).getBlock();

        auto recent = GetTime<std::chrono::seconds>() - std::chrono::seconds(STALE_TEMPLATE_GRACE_PERIOD);
        if (block.hashPrevBlock != m_best_prev_hash && m_last_block_time < recent) {
            LogTrace(BCLog::SV2, "Template id=%lu prevhash=%s, tip=%s\n", msg.m_template_id, HexStr(block.hashPrevBlock), HexStr(m_best_prev_hash));
            node::Sv2RequestTransactionDataErrorMsg request_tx_data_error{msg.m_template_id, "stale-template-id"};

            LogDebug(BCLog::SV2, "Send 0x75 RequestTransactionData.Error (stale-template-id) to client id=%zu\n",
                    client.m_id);
            LOCK(client.cs_send);
            client.m_send_messages.emplace_back(request_tx_data_error);
            return;
        }
    }

    std::vector<uint8_t> witness_reserve_value;
    auto scriptWitness = block.vtx[0]->vin[0].scriptWitness;
    if (!scriptWitness.IsNull()) {
        std::copy(scriptWitness.stack[0].begin(), scriptWitness.stack[0].end(), std::back_inserter(witness_reserve_value));
    }
    std::vector<CTransactionRef> txs;
    if (block.vtx.size() > 0) {
        std::copy(block.vtx.begin() + 1, block.vtx.end(), std::back_inserter(txs));
    }

    node::Sv2RequestTransactionDataSuccessMsg request_tx_data_success{msg.m_template_id, std::move(witness_reserve_value), std::move(txs)};

    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x74 RequestTransactionData.Success to client id=%zu\n",
                    client.m_id);
    LOCK(client.cs_send);
    client.m_send_messages.emplace_back(request_tx_data_success);
    m_connman->TryOptimisticSend(client);
}

void Sv2TemplateProvider::SubmitSolution(node::Sv2SubmitSolutionMsg solution)
{
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "id=%lu version=%d, timestamp=%d, nonce=%d\n",
            solution.m_template_id,
            solution.m_version,
            solution.m_ntime,
            solution.m_nonce
        );

        std::shared_ptr<BlockTemplate> block_template;
        {
            // We can't hold this lock until submitSolution() because it's
            // possible that the new block arrives via the p2p network at the
            // same time. That leads to a deadlock in g_best_block_mutex.
            LOCK(m_tp_mutex);
            auto cached_block_template = m_block_template_cache.find(solution.m_template_id);
            if (cached_block_template == m_block_template_cache.end()) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Template with id=%lu is no longer in cache\n",
                solution.m_template_id);
                return;
            }
            /**
             * It's important to not delete this template from the cache in case
             * another solution is submitted for the same template later.
             *
             * This is very unlikely on mainnet, but not impossible. Many mining
             * devices may be working on the default pool template at the same
             * time and they may not update the new tip right away.
             *
             * The node will never broadcast the second block. It's marked
             * valid-headers in getchaintips. However a node or pool operator
             * may wish to manually inspect the block or keep it as a souvenir.
             * Additionally, because in Stratum v2 the block solution is sent
             * to both the pool node and the template provider node, it's
             * possibly they arrive out of order and two competing blocks propagate
             * on the network. In case of a reorg the node will be able to switch
             * faster because it already has (but not fully validated) the block.
             */
            block_template = cached_block_template->second.second;
        }

        // Submit the solution to construct and process the block, using the
        // method that DetectNodeVersion() found.
        const CTransactionRef coinbase_tx{MakeTransactionRef(solution.m_coinbase_tx)};
        std::string reason, debug;
        bool submitted{false};

        if (m_node_version < NODE_VERSION_32_00) {
            submitted = block_template->submitSolutionOld7(solution.m_version,
                                                           solution.m_ntime,
                                                           solution.m_nonce,
                                                           coinbase_tx);
        } else {
            submitted = block_template->submitSolution(solution.m_version,
                                                       solution.m_ntime,
                                                       solution.m_nonce,
                                                       coinbase_tx,
                                                       reason,
                                                       debug);
        }

        if (!submitted) {
            LogWarning("Block was not accepted as a new block: %s%s\n",
                       reason.empty() ? std::string{"unknown reason"} : reason,
                       debug.empty() ? std::string{} : strprintf(" (%s)", debug));
        }

        SaveBlockAsync(block_template, submitted);
}

void Sv2TemplateProvider::SendToClient(size_t client_id, const node::Sv2NetMsg& msg)
{
    LOCK(m_connman->m_clients_mutex);
    const std::shared_ptr<Sv2Client> client{m_connman->GetClientById(client_id)};
    if (!client) return;
    LOCK(client->cs_send);
    client->m_send_messages.push_back(msg);
    m_connman->TryOptimisticSend(*client);
}

void Sv2TemplateProvider::SendProposeTemplateError(size_t client_id, uint32_t request_id, const std::string& code, const std::string& details)
{
    LogDebug(BCLog::SV2, "Send 0x7a ProposeTemplate.Error (%s) to client id=%zu\n", code, client_id);
    SendToClient(client_id, node::Sv2NetMsg{node::Sv2ProposeTemplateErrorMsg{request_id, code, details}});
}

void Sv2TemplateProvider::ProposeTemplate(Sv2Client& client, node::Sv2ProposeTemplateMsg msg)
{
    // Everything in the request originates from a miner the client does not
    // trust. The checks that need no node call run here, on the networking
    // thread. ThreadSv2ProposalHandler() does the rest.
    if (msg.m_wtxid_list.size() > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) return SendProposeTemplateError(client.m_id, msg.m_request_id, "bad-blk-length", "");
    if (std::set<Wtxid>(msg.m_wtxid_list.begin(), msg.m_wtxid_list.end()).size() != msg.m_wtxid_list.size()) return SendProposeTemplateError(client.m_id, msg.m_request_id, "duplicate-wtxid", "");

    Proposal proposal{.client_id = client.m_id, .request_id = msg.m_request_id, .version = msg.m_version};
    try {
        proposal.coinbase = MakeTransactionRef(msg.Coinbase());
    } catch (const std::ios_base::failure& e) {
        return SendProposeTemplateError(client.m_id, msg.m_request_id, "bad-cb-decode", e.what());
    }
    proposal.txs.resize(msg.m_wtxid_list.size());
    proposal.wtxids = std::move(msg.m_wtxid_list);
    QueueProposal(std::move(proposal));
}

void Sv2TemplateProvider::ProvideMissingTransactions(Sv2Client& client, node::Sv2ProvideMissingTransactionsSuccessMsg msg)
{
    std::optional<Proposal> found;
    {
        LOCK(m_tp_mutex);
        const auto pending{m_pending_proposals.find({client.m_id, msg.m_request_id})};
        if (pending != m_pending_proposals.end()) {
            if (pending->second.expires > GetTime<std::chrono::seconds>()) found = std::move(pending->second);
            m_pending_proposals.erase(pending);
        }
    }
    if (!found) return SendProposeTemplateError(client.m_id, msg.m_request_id, "unknown-request-id", "");
    Proposal proposal{std::move(*found)};

    // Each supplied transaction must be one we asked for. Check that before
    // any node call.
    std::map<Wtxid, size_t> requested;
    for (size_t i{0}; i < proposal.txs.size(); ++i) {
        if (!proposal.txs[i]) requested.emplace(proposal.wtxids[i], i);
    }
    for (const std::vector<uint8_t>& raw : msg.m_transaction_list) {
        CMutableTransaction mtx;
        try {
            DataStream ss{raw};
            ss >> TX_WITH_WITNESS(mtx);
            if (!ss.empty()) throw std::ios_base::failure("bytes after the transaction");
        } catch (const std::ios_base::failure& e) {
            return SendProposeTemplateError(client.m_id, msg.m_request_id, "bad-missing-tx", e.what());
        }
        CTransactionRef tx{MakeTransactionRef(std::move(mtx))};
        const auto position{requested.find(tx->GetWitnessHash())};
        if (position == requested.end()) return SendProposeTemplateError(client.m_id, msg.m_request_id, "bad-missing-tx", "transaction was not requested");
        proposal.txs[position->second] = std::move(tx);
        requested.erase(position);
    }
    if (!requested.empty()) return SendProposeTemplateError(client.m_id, msg.m_request_id, "bad-missing-tx", strprintf("%zu requested transactions not provided", requested.size()));

    QueueProposal(std::move(proposal));
}

void Sv2TemplateProvider::QueueProposal(Proposal proposal)
{
    const size_t client_id{proposal.client_id};
    const uint32_t request_id{proposal.request_id};
    std::string error_code, error_details;
    {
        LOCK(m_tp_mutex);
        const auto same_client{[client_id](const Proposal& p) { return p.client_id == client_id; }};
        const auto same_request{[&](const Proposal& p) { return same_client(p) && p.request_id == request_id; }};
        if (std::ranges::any_of(m_proposal_queue, same_request) || m_pending_proposals.contains({client_id, request_id})) {
            error_code = "duplicate-request-id";
        } else if (std::ranges::count_if(m_proposal_queue, same_client) >= static_cast<ptrdiff_t>(MAX_PROPOSALS_IN_FLIGHT)) {
            error_code = "job-validation-unavailable";
            error_details = strprintf("more than %zu proposals in flight", MAX_PROPOSALS_IN_FLIGHT);
        } else {
            m_proposal_queue.push_back(std::move(proposal));
        }
    }
    if (!error_code.empty()) return SendProposeTemplateError(client_id, request_id, error_code, error_details);
    m_proposal_cv.notify_one();
}

void Sv2TemplateProvider::ThreadSv2ProposalHandler()
{
    while (!m_flag_interrupt_sv2) {
        Proposal proposal;
        {
            WAIT_LOCK(m_tp_mutex, lock);
            // Bounded, so that an interrupt is noticed without a notification.
            if (!m_proposal_cv.wait_for(lock, 100ms, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex) { return !m_proposal_queue.empty(); })) continue;
            // Stays in the queue while being validated, so that it counts
            // towards MAX_PROPOSALS_IN_FLIGHT and duplicate-request-id.
            proposal = m_proposal_queue.front();
        }
        ValidateProposal(std::move(proposal));
        WITH_LOCK(m_tp_mutex, m_proposal_queue.pop_front());
    }
}

void Sv2TemplateProvider::ValidateProposal(Proposal proposal)
{
    const auto error{[&](const std::string& code, const std::string& details) {
        SendProposeTemplateError(proposal.client_id, proposal.request_id, code, details);
    }};

    try {
        // Until the node has caught up, a block on its tip is not worth
        // mining, and most of the mempool is missing.
        if (m_mining.isInitialBlockDownload()) return error("job-validation-unavailable", "initial block download");

        // Ask the node for whatever the client did not supply.
        std::vector<Wtxid> lookup;
        for (size_t i{0}; i < proposal.txs.size(); ++i) {
            if (!proposal.txs[i]) lookup.push_back(proposal.wtxids[i]);
        }
        if (!lookup.empty()) {
            const std::vector<CTransactionRef> found{m_mining.getTransactionsByWitnessID(lookup)};
            size_t next{0};
            for (CTransactionRef& tx : proposal.txs) {
                if (!tx) tx = found.at(next++);
            }
        }

        node::Sv2ProvideMissingTransactionsMsg missing{proposal.request_id, {}};
        for (size_t i{0}; i < proposal.txs.size(); ++i) {
            if (!proposal.txs[i]) missing.m_unknown_tx_position_list.push_back(static_cast<uint16_t>(i));
        }
        if (!missing.m_unknown_tx_position_list.empty()) {
            LogDebug(BCLog::SV2, "Send 0x78 ProvideMissingTransactions (%zu of %zu) to client id=%zu\n",
                     missing.m_unknown_tx_position_list.size(), proposal.txs.size(), proposal.client_id);
            const size_t client_id{proposal.client_id};
            const uint32_t request_id{proposal.request_id};
            {
                LOCK(m_tp_mutex);
                const auto now{GetTime<std::chrono::seconds>()};
                std::erase_if(m_pending_proposals, [now](const auto& kv) { return kv.second.expires <= now; });
                // Forget the client's oldest request if it has too many.
                const auto first{m_pending_proposals.lower_bound({client_id, 0})};
                const auto last{m_pending_proposals.lower_bound({client_id + 1, 0})};
                if (std::distance(first, last) >= static_cast<ptrdiff_t>(MAX_PENDING_PROPOSALS)) {
                    m_pending_proposals.erase(std::min_element(first, last, [](const auto& a, const auto& b) { return a.second.expires < b.second.expires; }));
                }
                proposal.expires = now + PENDING_PROPOSAL_TIMEOUT;
                m_pending_proposals.insert_or_assign({client_id, request_id}, std::move(proposal));
            }
            return SendToClient(client_id, node::Sv2NetMsg{missing});
        }

        CBlock block;
        block.vtx.push_back(proposal.coinbase);
        block.vtx.insert(block.vtx.end(), proposal.txs.begin(), proposal.txs.end());

        // The block is checked on the node's tip, so it needs that tip's hash,
        // nBits and a usable nTime. An empty template is the cheapest way to get
        // a header for it through the mining interface.
        const std::unique_ptr<BlockTemplate> tip_template{m_mining.createNewBlock({.use_mempool = false}, /*cooldown=*/false)};
        if (!tip_template) return error("job-validation-unavailable", "node is shutting down");
        const CBlockHeader tip_header{tip_template->getBlockHeader()};
        block.hashPrevBlock = tip_header.hashPrevBlock;
        block.nBits = tip_header.nBits;
        block.nTime = tip_header.nTime;
        block.nVersion = static_cast<int32_t>(proposal.version);

        std::string reason, debug;
        if (!m_mining.checkBlock(block, {.check_merkle_root = false, .check_pow = false}, reason, debug)) {
            return error(reason, debug);
        }

        const uint256 prev_hash{block.hashPrevBlock};
        uint64_t template_id;
        {
            LOCK(m_tp_mutex);
            // The node checked the block on its tip, so for cache pruning that
            // is the best tip we know of, as when a template arrives.
            if (prev_hash != m_best_prev_hash) {
                m_best_prev_hash = prev_hash;
                m_last_block_time = GetTime<std::chrono::seconds>();
            }
            template_id = ++m_template_id;
            m_block_template_cache.insert({template_id, std::make_pair(prev_hash, std::make_shared<ProposedBlockTemplate>(m_mining, std::move(block)))});
        }

        // The mining interface does not return the fee total for a block it only
        // checked: checkBlock() yields a reason and debug string, and a template
        // made from a client's transaction list cannot answer getTxFees(). Send 0
        // (unknown) until Core exposes it, see bitcoin/bitcoin#35671.
        LogDebug(BCLog::SV2, "Send 0x79 ProposeTemplate.Success id=%lu to client id=%zu\n", template_id, proposal.client_id);
        SendToClient(proposal.client_id, node::Sv2NetMsg{node::Sv2ProposeTemplateSuccessMsg{proposal.request_id, template_id, prev_hash, /*fees=*/0}});
    } catch (const std::exception& e) {
        // Usually the node connection was lost, which the main thread notices
        // and handles, so log at Debug only.
        LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Could not validate proposal request_id=%u from client id=%zu: %s\n",
                      proposal.request_id, proposal.client_id, e.what());
        error("job-validation-unavailable", e.what());
    }
}

void Sv2TemplateProvider::SaveBlockAsync(std::shared_ptr<BlockTemplate> block_template, bool submitted)
{
    // Briefly wait (so we can focus on the next template) and then fetch and
    // store the block for debugging purposes.
    std::thread(&util::TraceThread, "sv2-saveblk",
                [block_template = std::move(block_template), submitted]() mutable {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
        try {
            // Retrieve block after delay
            const CBlock block{block_template->getBlock()};
            const uint256 block_hash = block.GetHash();
            const fs::path out_path = gArgs.GetDataDirNet() / (block_hash.ToString() + ".dat").c_str();

            // Serialize block including witness data
            std::vector<unsigned char> block_data;
            VectorWriter writer{block_data, 0};
            writer << TX_WITH_WITNESS(block);
            const std::string bytes{reinterpret_cast<const char*>(block_data.data()), block_data.size()};

            if (!WriteBinaryFile(out_path, bytes)) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Error,
                              "Failed to write block %s to %s\n",
                              block_hash.ToString(), fs::PathToString(out_path));
            } else {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Debug,
                              "Wrote block %s to %s (submitted=%d)\n",
                              block_hash.ToString(), fs::PathToString(out_path), submitted);
            }
        } catch (const std::exception& e) {
            LogPrintLevel(BCLog::SV2, BCLog::Level::Error,
                          "sv2-saveblk thread caught exception: %s\n", e.what());
        }
    }).detach();
}

void Sv2TemplateProvider::PruneBlockTemplateCache()
{
    AssertLockHeld(m_tp_mutex);

    auto recent = GetTime<std::chrono::seconds>() - std::chrono::seconds(STALE_TEMPLATE_GRACE_PERIOD);
    if (m_last_block_time > recent) return;
    // If the blocks prevout is not the tip's prevout, delete it.
    uint256 prev_hash = m_best_prev_hash;
    std::erase_if(m_block_template_cache, [prev_hash] (const auto& kv) {
        if (kv.second.first != prev_hash) {
            LogTrace(BCLog::SV2, "Prune stale template id=%lu (%zus after new tip)", kv.first, STALE_TEMPLATE_GRACE_PERIOD);
            return true;
        }
        return false;
    });
}

bool Sv2TemplateProvider::SendWork(Sv2Client& client, uint64_t template_id, BlockTemplate& block_template, bool future_template)
{
    CBlockHeader header{block_template.getBlockHeader()};
    node::CoinbaseTx coinbase{block_template.getCoinbaseTx()};

    node::Sv2NewTemplateMsg new_template{header,
                                         coinbase,
                                         block_template.getCoinbaseMerklePath(),
                                         template_id,
                                         future_template};

    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x71 NewTemplate id=%lu future=%d to client id=%zu\n", template_id, future_template, client.m_id);
    {
        LOCK(client.cs_send);
        client.m_send_messages.emplace_back(new_template);

        if (future_template) {
            node::Sv2SetNewPrevHashMsg new_prev_hash{header, template_id};
            LogPrintLevel(BCLog::SV2, BCLog::Level::Debug, "Send 0x72 SetNewPrevHash to client id=%zu\n", client.m_id);
            client.m_send_messages.emplace_back(new_prev_hash);
        }

        m_connman->TryOptimisticSend(client);
    }

    CAmount total_fees{0};
    for (const CAmount fee : block_template.getTxFees()) {
        total_fees += fee;
    }
    LogPrintLevel(BCLog::SV2, BCLog::Level::Debug,
                  "Template %lu includes %lld sat in fees\n",
                  template_id,
                  static_cast<long long>(total_fees));

    return true;
}
