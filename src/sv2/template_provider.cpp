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

#include <algorithm>
#include <limits>

// Allow a few seconds for clients to submit a block or to request transactions
constexpr size_t STALE_TEMPLATE_GRACE_PERIOD{10};

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

   // Generate self signed certificate using (cached) authority key
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
    Sv2SignatureNoiseMessage certificate = Sv2SignatureNoiseMessage(version, valid_from, valid_to, XOnlyPubKey(static_key.GetPubKey()), authority_key);

    m_connman = std::make_unique<Sv2Connman>(TP_SUBPROTOCOL, static_key, m_authority_pubkey, certificate);
}

fs::path Sv2TemplateProvider::GetStaticKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_static_key";
}

fs::path Sv2TemplateProvider::GetAuthorityKeyFile()
{
    return gArgs.GetDataDirNet() / "sv2_authority_key";
}

bool Sv2TemplateProvider::Start(const Sv2TemplateProviderOptions& options)
{
    m_options = options;

    if (!m_connman->Start(this, m_options.host, m_options.port)) {
        return false;
    }

    m_thread_sv2_handler = std::thread(&util::TraceThread, "sv2", [this] { ThreadSv2Handler(); });
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

void Sv2TemplateProvider::Interrupt()
{
    AssertLockNotHeld(m_tp_mutex);

    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Interrupt pending waitNext() calls...");
    {
        LOCK(m_tp_mutex);
        try {
            for (auto& t : GetBlockTemplates()) {
                t.second.second->interruptWait();
            }
        } catch (const ipc::Exception& e) {
            // Bitcoin Core v30 does not yet implement interruptWait(), fall back
            // to just waiting until waitNext() returns.
            LogPrintLevel(BCLog::SV2, BCLog::Level::Info,
                          "Interrupt received, waiting up to %d seconds before shutting down (-sv2interval)",
                          m_options.fee_check_interval.count());
        }
    }

    m_flag_interrupt_sv2 = true;
    // Also interrupt network threads so client handlers can wind down quickly.
    if (m_connman) m_connman->Interrupt();
}

void Sv2TemplateProvider::StopThreads()
{
    if (m_thread_sv2_handler.joinable()) {
        m_thread_sv2_handler.join();
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
        if (!m_mining.isInitialBlockDownload()) break;
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

        m_connman->ForEachClient([this, &client_threads](Sv2Client& client) {
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
    try {
        Timer timer(m_options.fee_check_interval);

        const auto prepare_block_create_options = [this, client_id](node::BlockCreateOptions& options) -> bool {
            {
                LOCK(m_connman->m_clients_mutex);
                std::shared_ptr client = m_connman->GetClientById(client_id);
                if (!client) return false;

                // https://stratumprotocol.org/specification/07-Template-Distribution-Protocol#71-coinbaseoutputconstraints-client-server
                // Weight units reserved for block header, transaction count,
                // and various fixed and variable coinbase fields.
                const size_t block_reserved_floor{1168};
                // Reserve a little more so that if the above calculation is
                // wrong or there's an implementation error, we don't produce
                // an invalid bock when the template is completely full.
                const size_t block_reserved_padding{400};

                // Bitcoin Core enforces a mimimum -blockreservedweight of 2000,
                // but via IPC we can go below that.
                options.block_reserved_weight = block_reserved_floor +
                                                block_reserved_padding +
                                                client->m_coinbase_tx_outputs_size * 4;

            }
            return true;
        };

        std::shared_ptr<BlockTemplate> block_template;
        // Cache most recent block_template->getBlockHeader().hashPrevBlock result.
        uint256 prev_hash;
        while (!m_flag_interrupt_sv2) {
            if (!block_template) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Generate initial block template for client id=%zu\n",
                            client_id);

                // Create block template and store interface reference
                // TODO: reuse template_id for clients with the same coinbase constraints
                uint64_t template_id{WITH_LOCK(m_tp_mutex, return ++m_template_id;)};

                node::BlockCreateOptions block_create_options{.use_mempool = true};
                if (!prepare_block_create_options(block_create_options)) break;

                const auto time_start{SteadyClock::now()};
                block_template = m_mining.createNewBlock(block_create_options);
                if (!block_template) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "No new template for client id=%zu, node is shutting down\n",
                        client_id);
                    break;
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

            // -sv2interval=N requires that we don't send fee updates until at least
            // N seconds have gone by. So we first call waitNext() without a fee
            // threshold, and then on the next while iteration we set it.
            // TODO: add test coverage
            const bool check_fees{m_options.is_test || timer.trigger()};

            CAmount fee_delta{check_fees ? m_options.fee_delta : MAX_MONEY};

            node::BlockWaitOptions options;
            options.fee_threshold = fee_delta;
            // Always set a timeout so Ctrl+C interrupts within a bounded time.
            options.timeout = m_options.is_test ? MillisecondsDouble(1000) : m_options.fee_check_interval;
            if (!check_fees) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                              "Ignore fee changes for %d seconds (-sv2interval), wait for a new tip, client id=%zu\n",
                              m_options.fee_check_interval.count(), client_id);
            } else {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                              "Wait up to %d seconds for fees to rise by %lld sat or a new tip, client id=%zu\n",
                              m_options.fee_check_interval.count(),
                              static_cast<long long>(fee_delta),
                              client_id);
            }

            std::shared_ptr<BlockTemplate> tmpl = block_template->waitNext(options);
            // The client may have disconnected during the wait, check now to avoid
            // a spurious IPC call and confusing log statements.
            {
                LOCK(m_connman->m_clients_mutex);
                if (!m_connman->GetClientById(client_id)) break;
            }

            // After timeout and during node shutdown this is expect to not be set
            if (tmpl) {
                block_template = tmpl;
                uint256 new_prev_hash{block_template->getBlockHeader().hashPrevBlock};

                {
                    LOCK(m_tp_mutex);
                    if (new_prev_hash != m_best_prev_hash) {
                        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Tip changed, client id=%zu\n",
                            client_id);
                        future_template = true;
                        m_best_prev_hash = new_prev_hash;
                        // Does not need to be accurate
                        m_last_block_time = GetTime<std::chrono::seconds>();
                    }

                    ++m_template_id;

                    // Add template to cache before sending it, to prevent race
                    // condition: https://github.com/stratum-mining/stratum/issues/1773
                    m_block_template_cache.insert({m_template_id, std::make_pair(new_prev_hash,block_template)});
                }

                {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;

                    if (!SendWork(*client, WITH_LOCK(m_tp_mutex, return m_template_id;), *block_template, future_template)) {
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
    } catch (const std::exception& e) {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                      "Client thread for id=%zu exiting after exception: %s\n",
                      client_id, e.what());
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
            solution.m_header_timestamp,
            solution.m_header_nonce
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

        // Submit the solution to construct and process the block
        const bool submitted = block_template->submitSolution(
            solution.m_version,
            solution.m_header_timestamp,
            solution.m_header_nonce,
            MakeTransactionRef(solution.m_coinbase_tx));

        SaveBlockAsync(block_template, submitted);
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

    // On signet, ensure the segwit commitment is present; otherwise, submitting a solution will fail.
    if (gArgs.GetBoolArg("-signet", false) && block_template.getWitnessCommitmentIndex() == NO_WITNESS_COMMITMENT) {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Error,
                      "Refusing to send NewTemplate on signet without segwit commitment (id=%lu)\n",
                      template_id);
        return false;
    }

    node::Sv2NewTemplateMsg new_template{header,
                                        block_template.getCoinbaseTx(),
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
