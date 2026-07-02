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

#include <algorithm>
#include <limits>

namespace {

constexpr auto WAIT_NEXT_RETRY_INITIAL_DELAY{100ms};
constexpr auto WAIT_NEXT_RETRY_MAX_DELAY{1000ms};

// Keep probing the backend even when no client handler is making template IPC calls.
constexpr auto BACKEND_LIVENESS_CHECK_INTERVAL{1000ms};
}

Sv2TemplateProvider::BackendSession::BackendSession(std::unique_ptr<interfaces::Init> init,
                                                    std::unique_ptr<interfaces::Mining> mining) :
    m_init(std::move(init)),
    m_mining(std::move(mining))
{
}

// Allow a few seconds for clients to submit a block or to request transactions
constexpr size_t STALE_TEMPLATE_GRACE_PERIOD{10};

void Sv2TemplateProvider::ReplaceBackend(std::unique_ptr<interfaces::Init> node_init,
                                         std::unique_ptr<interfaces::Mining> mining)
{
    auto backend = std::make_shared<BackendSession>(std::move(node_init), std::move(mining));
    {
        LOCK(m_backend_mutex);
        LOCK(m_tp_mutex);

        // Cached templates belong to a specific IPC backend generation. Drop
        // old proxies before publishing the replacement backend.
        ClearTemplateCache(/*log_dropped_templates=*/true);
        m_backend = backend;
    }
    m_backend_cv.notify_all();
}

bool Sv2TemplateProvider::BackendConnected()
{
    LOCK(m_backend_mutex);
    return m_backend != nullptr;
}

std::shared_ptr<Sv2TemplateProvider::BackendSession> Sv2TemplateProvider::WaitForBackend()
{
    WAIT_LOCK(m_backend_mutex, lock);
    while (!m_flag_interrupt_sv2 && !m_backend) {
        m_backend_cv.wait(lock);
    }
    if (m_flag_interrupt_sv2) return nullptr;
    return m_backend;
}

void Sv2TemplateProvider::DisconnectBackend(const std::shared_ptr<BackendSession>& backend,
                                            const char* operation,
                                            const std::exception& exception)
{
    if (!backend) return;

    // Multiple client threads can observe the same backend failure. Only the
    // first one should clear state and log the disconnect at error level.
    const bool first_disconnect = backend->MarkDisconnected();
    std::shared_ptr<BackendSession> active_backend;
    {
        LOCK(m_backend_mutex);
        if (m_backend == backend) {
            active_backend = m_backend;
            m_backend.reset();
        }
    }
    if (!active_backend) return;

    {
        LOCK(m_tp_mutex);
        ClearTemplateCache(/*log_dropped_templates=*/true);
    }

    if (first_disconnect) {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Error,
                      "Bitcoin Core IPC connection lost during %s: %s\n",
                      operation, exception.what());
    } else {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace,
                      "Ignoring repeated Bitcoin Core IPC failure during %s: %s\n",
                      operation, exception.what());
    }

    m_backend_cv.notify_all();
}

void Sv2TemplateProvider::InterruptBackend()
{
    std::shared_ptr<BackendSession> backend;
    {
        LOCK(m_backend_mutex);
        backend = m_backend;
    }
    if (!backend) return;

    InterruptTemplateWaits();
    try {
        backend->Mining().interrupt();
    } catch (const ipc::Exception& e) {
        DisconnectBackend(backend, "interrupt", e);
    }
}

void Sv2TemplateProvider::InterruptTemplateWaits()
{
    std::shared_ptr<BackendSession> backend;
    std::vector<std::shared_ptr<BlockTemplate>> templates_to_interrupt;
    {
        LOCK(m_backend_mutex);
        backend = m_backend;
    }
    if (!backend) return;

    {
        LOCK(m_tp_mutex);
        for (const auto& cached : m_block_template_cache) {
            const auto& cached_template{cached.second};
            if (cached_template.wait_next_in_progress) {
                templates_to_interrupt.push_back(cached_template.block_template);
            }
        }
    }

    for (const auto& block_template : templates_to_interrupt) {
        try {
            block_template->interruptWait();
        } catch (const ipc::Exception& e) {
            DisconnectBackend(backend, "interruptWait", e);
        }
    }
}

Sv2TemplateProvider::Sv2TemplateProvider()
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

    Interrupt();
    m_connman->StopThreads();
    StopThreads();
    {
        LOCK(m_backend_mutex);
        if (m_backend) {
            m_backend->MarkDisconnected();
            m_backend.reset();
        }
    }
    {
        LOCK(m_tp_mutex);
        ClearTemplateCache(/*log_dropped_templates=*/false);
    }
    m_backend_cv.notify_all();
}

void Sv2TemplateProvider::Interrupt()
{
    AssertLockNotHeld(m_tp_mutex);

    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Interrupt pending mining waits...");
    m_flag_interrupt_sv2 = true;
    m_interrupt_sv2();
    m_backend_cv.notify_all();
    InterruptBackend();
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

void Sv2TemplateProvider::ClearTemplateCache(bool log_dropped_templates)
{
    AssertLockHeld(m_tp_mutex);
    if (log_dropped_templates && !m_block_template_cache.empty()) {
        LogPrintLevel(BCLog::SV2, BCLog::Level::Warning,
                      "Dropping %zu cached block templates after Bitcoin Core IPC backend reset\n",
                      m_block_template_cache.size());
    }
    m_block_template_cache.clear();
    m_best_prev_hash = uint256::ZERO;
    m_last_block_time = GetTime<std::chrono::seconds>();
}

void Sv2TemplateProvider::ThreadSv2Handler()
{
    // Make sure it's initialized, doesn't need to be accurate.
    {
        LOCK(m_tp_mutex);
        m_last_block_time = GetTime<std::chrono::seconds>();
    }

    std::map<size_t, std::thread> client_threads;
    std::shared_ptr<BackendSession> checked_ibd_backend;
    auto next_backend_liveness_check{SteadyClock::now()};

    while (!m_flag_interrupt_sv2) {
        std::shared_ptr<BackendSession> backend;
        {
            LOCK(m_backend_mutex);
            backend = m_backend;
        }

        // Wait to come out of IBD, except on signet, where we might be the only miner.
        if (backend != checked_ibd_backend && gArgs.GetChainType() != ChainType::SIGNET) {
            if (SteadyClock::now() < next_backend_liveness_check) {
                std::this_thread::sleep_for(100ms);
                continue;
            }
            next_backend_liveness_check = SteadyClock::now() + BACKEND_LIVENESS_CHECK_INTERVAL;
            try {
                // TODO: Wait until there's no headers-only branch with more work than our chaintip.
                //       The current check can still cause us to broadcast a few dozen useless templates
                //       at startup.
                if (backend && backend->Mining().isInitialBlockDownload()) {
                    continue;
                }
            } catch (const ipc::Exception& e) {
                DisconnectBackend(backend, "template provider main loop", e);
                continue;
            }
            checked_ibd_backend = backend;
        } else if (backend && SteadyClock::now() >= next_backend_liveness_check) {
            next_backend_liveness_check = SteadyClock::now() + BACKEND_LIVENESS_CHECK_INTERVAL;
            try {
                // Detect backend shutdown even when no client handler is making IPC calls.
                backend->Mining().getTip();
            } catch (const ipc::Exception& e) {
                DisconnectBackend(backend, "template provider liveness check", e);
                continue;
            }
        }

        m_connman->ForEachClient([this, &client_threads](Sv2Client& client) {
            /**
             * The initial handshake is handled on the Sv2Connman thread. This
             * consists of the noise protocol handshake and the initial Stratum
             * v2 messages SetupConnection and CoinbaseOutputConstraints.
             */
            if (!client.m_coinbase_output_constraints_recv) return;

            if (client_threads.contains(client.m_id)) return;

            const size_t client_id = client.m_id;
            client_threads.emplace(client_id,
                                   std::thread(&util::TraceThread,
                                               strprintf("sv2-%zu", client_id),
                                               [this, client_id] { ThreadSv2ClientHandler(client_id); }));
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
        Timer timer(m_options.template_interval);
        auto wait_next_retry_delay{WAIT_NEXT_RETRY_INITIAL_DELAY};

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
                // an invalid block when the template is completely full.
                const size_t block_reserved_padding{400};

                // Bitcoin Core enforces a minimum block reserved weight of 2000.
                options.block_reserved_weight = std::max(
                    node::MIN_BLOCK_RESERVED_WEIGHT,
                    block_reserved_floor + block_reserved_padding + client->m_coinbase_tx_outputs_size * 4);
            }
            return true;
        };

        // We start with one template per client, which has an interface through
        // which we monitor for better templates.
        std::shared_ptr<BlockTemplate> block_template;
        std::shared_ptr<BackendSession> backend;
        std::shared_ptr<BackendSession> template_backend;
        // Cache most recent block_template->getBlockHeader().hashPrevBlock result.
        uint256 prev_hash;
        uint64_t current_template_id{0};

        // Track the coinbase constraints generation that was active when block_template was built.
        uint64_t constraints_generation_at_build = 0;
        while (!m_flag_interrupt_sv2) {
            if (!backend) {
                backend = WaitForBackend();
                if (!backend) break;
            }

            if (backend->Disconnected()) {
                backend.reset();
                block_template.reset();
                template_backend.reset();
                current_template_id = 0;
                continue;
            }

            if (template_backend && template_backend != backend) {
                block_template.reset();
                template_backend.reset();
                current_template_id = 0;
            }

            if (!block_template) {
                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "%s block template for client id=%zu\n", constraints_generation_at_build == 0 ? "Generate initial" : "Regenerate", client_id);

                // Create block template and store interface reference
                uint64_t template_id{WITH_LOCK(m_tp_mutex, return ++m_template_id;)};

                node::BlockCreateOptions block_create_options{.use_mempool = true};
                if (!prepare_block_create_options(block_create_options)) break;

                const auto time_start{SteadyClock::now()};
                try {
                    block_template = backend->Mining().createNewBlock(block_create_options);
                } catch (const ipc::Exception& e) {
                    DisconnectBackend(backend, "createNewBlock", e);
                    backend.reset();
                    continue;
                }
                if (!block_template) {
                    LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "No new template for client id=%zu, node is shutting down\n",
                        client_id);
                    break;
                }
                template_backend = backend;

                {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;
                    constraints_generation_at_build = client->m_coinbase_constraints_generation.load();
                }

                LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Assemble template: %.2fms\n",
                    Ticks<MillisecondsDouble>(SteadyClock::now() - time_start));

                try {
                    prev_hash = block_template->getBlockHeader().hashPrevBlock;
                } catch (const ipc::Exception& e) {
                    DisconnectBackend(backend, "getBlockHeader", e);
                    backend.reset();
                    continue;
                }
                {
                    LOCK(m_tp_mutex);
                    if (prev_hash != m_best_prev_hash) {
                        m_best_prev_hash = prev_hash;
                        // Does not need to be accurate
                        m_last_block_time = GetTime<std::chrono::seconds>();
                    }

                    // Add template to cache before sending it, to prevent race
                    // condition: https://github.com/stratum-mining/stratum/issues/1773
                    m_block_template_cache.insert({template_id, {prev_hash, block_template}});
                    current_template_id = template_id;
                }

                try {
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
                } catch (const ipc::Exception& e) {
                    DisconnectBackend(backend, "SendWork", e);
                    backend.reset();
                    continue;
                }

                timer.reset();
                wait_next_retry_delay = WAIT_NEXT_RETRY_INITIAL_DELAY;
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

            std::shared_ptr<BlockTemplate> tmpl;
            const auto set_wait_next_in_progress = [&](bool in_progress) {
                LOCK(m_tp_mutex);
                auto it = m_block_template_cache.find(current_template_id);
                if (it == m_block_template_cache.end()) return false;
                it->second.wait_next_in_progress = in_progress;
                return true;
            };

            if (!set_wait_next_in_progress(true)) break;
            try {
                tmpl = block_template->waitNext(options);
            } catch (const ipc::Exception& e) {
                set_wait_next_in_progress(false);
                DisconnectBackend(template_backend, "template provider client loop", e);
                backend.reset();
                block_template.reset();
                template_backend.reset();
                continue;
            }
            set_wait_next_in_progress(false);
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

            // After timeout and during node shutdown this is expected to not be set.
            // Back off when shutdown causes waitNext() to return immediately, to
            // avoid repeatedly calling into a backend that is going away.
            if (!tmpl) {
                if (!m_interrupt_sv2.sleep_for(wait_next_retry_delay)) break;
                wait_next_retry_delay = std::min(wait_next_retry_delay * 2, WAIT_NEXT_RETRY_MAX_DELAY);
                continue;
            }

            if (tmpl) {
                block_template = tmpl;
                template_backend = backend;

                uint256 new_prev_hash;
                try {
                    new_prev_hash = block_template->getBlockHeader().hashPrevBlock;
                } catch (const ipc::Exception& e) {
                    DisconnectBackend(template_backend, "getBlockHeader", e);
                    backend.reset();
                    block_template.reset();
                    template_backend.reset();
                    continue;
                }

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

                    current_template_id = ++m_template_id;

                    // Add template to cache before sending it, to prevent race
                    // condition: https://github.com/stratum-mining/stratum/issues/1773
                    m_block_template_cache.insert({current_template_id, {new_prev_hash, block_template}});
                }

                try {
                    LOCK(m_connman->m_clients_mutex);
                    std::shared_ptr client = m_connman->GetClientById(client_id);
                    if (!client) break;

                    if (client->m_coinbase_constraints_generation.load() != constraints_generation_at_build) {
                        block_template = nullptr;
                        continue;
                    }
                    if (!SendWork(*client, current_template_id, *block_template, future_template)) {
                        LogPrintLevel(BCLog::SV2, BCLog::Level::Trace, "Disconnecting client id=%zu\n",
                                    client_id);
                        LOCK(client->cs_status);
                        client->m_disconnect_flag = true;
                    }
                } catch (const ipc::Exception& e) {
                    DisconnectBackend(template_backend, "SendWork", e);
                    backend.reset();
                    block_template.reset();
                    template_backend.reset();
                    continue;
                }

                timer.reset();
                wait_next_retry_delay = WAIT_NEXT_RETRY_INITIAL_DELAY;
            }

            if (m_options.is_test) {
                // Take a break
                std::this_thread::sleep_for(50ms);
            }
        }
        {
            LOCK(m_tp_mutex);
            if (current_template_id != 0) {
                auto it = m_block_template_cache.find(current_template_id);
                if (it != m_block_template_cache.end()) {
                    it->second.wait_next_in_progress = false;
                }
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
    std::shared_ptr<BlockTemplate> block_template;
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
        block_template = cached_block->second.block_template;
    }
    try {
        block = block_template->getBlock();
    } catch (const ipc::Exception& e) {
        std::shared_ptr<BackendSession> backend;
        {
            LOCK(m_backend_mutex);
            backend = m_backend;
        }
        DisconnectBackend(backend, "getBlock", e);
        return;
    }

    {
        LOCK(m_tp_mutex);
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
            block_template = cached_block_template->second.block_template;
        }

        // Submit the solution to construct and process the block
        bool submitted{false};
        try {
            submitted = block_template->submitSolution(
                solution.m_version,
                solution.m_header_timestamp,
                solution.m_header_nonce,
                MakeTransactionRef(solution.m_coinbase_tx));
        } catch (const ipc::Exception& e) {
            std::shared_ptr<BackendSession> backend;
            {
                LOCK(m_backend_mutex);
                backend = m_backend;
            }
            DisconnectBackend(backend, "submitSolution", e);
            return;
        }

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
        } catch (const ipc::Exception& e) {
             LogPrintLevel(BCLog::SV2, BCLog::Level::Error,
                          "sv2-saveblk thread caught IPC exception: %s\n", e.what());
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
    // If the block's prevout is not the tip's prevout, delete it. Keep entries
    // with waitNext() in progress so InterruptTemplateWaits() can still find
    // and wake the blocking call.
    uint256 prev_hash = m_best_prev_hash;
    std::erase_if(m_block_template_cache, [prev_hash] (const auto& kv) {
        if (kv.second.prev_hash != prev_hash && !kv.second.wait_next_in_progress) {
            LogTrace(BCLog::SV2, "Prune stale template id=%lu (%zus after new tip)", kv.first, STALE_TEMPLATE_GRACE_PERIOD);
            return true;
        }
        return false;
    });
}

bool Sv2TemplateProvider::SendWork(Sv2Client& client, uint64_t template_id, BlockTemplate& block_template, bool future_template)
{
    CBlockHeader header;
    node::CoinbaseTx coinbase;
    try {
        header = block_template.getBlockHeader();
        coinbase = block_template.getCoinbaseTx();
    } catch (const ipc::Exception& e) {
        throw;
    }

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
