#ifndef BITCOIN_SV2_TEMPLATE_PROVIDER_H
#define BITCOIN_SV2_TEMPLATE_PROVIDER_H

#include <chrono>
#include <interfaces/init.h>
#include <interfaces/mining.h>
#include <sv2/connman.h>
#include <sv2/messages.h>
#include <logging.h>
#include <net.h>
#include <util/sock.h>
#include <util/time.h>
#include <streams.h>
#include <memory>
#include <atomic>
#include <condition_variable>

using interfaces::BlockTemplate;

class CBlock;

struct Sv2TemplateProviderOptions
{
    /**
     * Running inside a test
     */
    bool is_test{false};

    /**
     * Host for the server to bind to.
     */
    std::string host{"127.0.0.1"};

    /**
     * The listening port for the server.
     */
    uint16_t port{8336};

    /**
     * Minimum fee delta to send new template upstream
     */
    CAmount fee_delta{1000};

    /**
     * Minimum seconds between fee-based template updates.
     * New blocks always propagate immediately.
     */
    std::chrono::seconds template_interval{5};
};

/**
 * The main class that runs the template provider server.
 */
class Sv2TemplateProvider : public Sv2EventsInterface
{

private:
    /**
    * The active Bitcoin Core IPC backend generation.
    */
    struct BackendSession {
        explicit BackendSession(std::unique_ptr<interfaces::Init> init, std::unique_ptr<interfaces::Mining> mining);

        /**
         * Mark the backend session disconnected.
         * Returns true the first time it is called.
         */
        bool MarkDisconnected()
        {
            return !m_disconnected.exchange(true);
        }

        /**
         * Whether the backend session has been disconnected.
         */
        bool Disconnected() const
        {
            return m_disconnected.load();
        }

        /**
         * The mining interface for this backend session.
         */
        interfaces::Mining& Mining()
        {
            return *m_mining;
        }

    private:
        /**
         * Whether this backend session has already been disconnected.
         */
        std::atomic<bool> m_disconnected{false};

        /**
         * Init interface held to keep the IPC backend session alive.
         */
        std::unique_ptr<interfaces::Init> m_init;

        /**
         * Mining interface for this backend session.
         */
        std::unique_ptr<interfaces::Mining> m_mining;
    };

    /*
     * The template provider subprotocol used in setup connection messages. The stratum v2
     * template provider only recognizes its own subprotocol.
     */
    static constexpr uint8_t TP_SUBPROTOCOL{0x02};

    std::unique_ptr<Sv2Connman> m_connman;

    /** Get name of file to store static key */
    fs::path GetStaticKeyFile();

    /** Get name of file to store authority key */
    fs::path GetAuthorityKeyFile();

    /**
    * Configuration
    */
    Sv2TemplateProviderOptions m_options;

    /**
     * The main thread for the template provider.
     */
    std::thread m_thread_sv2_handler;

    /**
     * Signal for handling interrupts and stopping the template provider event loop.
     */
    std::atomic<bool> m_flag_interrupt_sv2{false};
    CThreadInterrupt m_interrupt_sv2;

    /**
     * Mutex guarding the active backend session.
     */
    Mutex m_backend_mutex;

    /**
     * Condition variable notified when the active backend session changes.
     */
    std::condition_variable_any m_backend_cv;

    /**
     * The active backend session.
     */
    std::shared_ptr<BackendSession> m_backend GUARDED_BY(m_backend_mutex);

    /**
     * The most recent template id. This is incremented on creating new template,
     * which happens for each connected client.
     */
    uint64_t m_template_id GUARDED_BY(m_tp_mutex){0};

    /**
     * The current best known block hash in the network.
     */
    uint256 m_best_prev_hash GUARDED_BY(m_tp_mutex){uint256(0)};

    /** When we last saw a new block connection. Used to cache stale templates
      * for some time after this.
      */
    std::chrono::nanoseconds m_last_block_time GUARDED_BY(m_tp_mutex);

    /**
     * Template state kept for each id sent in a NewTemplate message.
     */
    struct CachedBlockTemplate {
        uint256 prev_hash;
        std::shared_ptr<BlockTemplate> block_template;
        bool wait_next_in_progress{false};
    };

    /**
     * Cache of templates that connected clients may still be working on.
     *
     * wait_next_in_progress is tracked here, not in Sv2Client, so the template
     * provider can interrupt only active waitNext() calls without guessing from
     * the client's most recently sent template.
     */
    using BlockTemplateCache = std::map<uint64_t, CachedBlockTemplate>;
    BlockTemplateCache m_block_template_cache GUARDED_BY(m_tp_mutex);

public:
    Sv2TemplateProvider();

    ~Sv2TemplateProvider() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex, !m_backend_mutex);

    Mutex m_tp_mutex;

    /**
     * Starts the template provider server and thread.
     * returns false if port is unable to bind.
     */
    [[nodiscard]] bool Start(const Sv2TemplateProviderOptions& options = {});

    /**
     * Whether there is a connected backend session.
     */
    bool BackendConnected() EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex);

    /**
     * Replace the active backend session.
     */
    void ReplaceBackend(std::unique_ptr<interfaces::Init> node_init,
                        std::unique_ptr<interfaces::Mining> mining) EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex, !m_tp_mutex);

    /**
     * The main thread for the template provider, contains an event loop handling
     * all tasks for the template provider.
     */
    void ThreadSv2Handler() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex, !m_backend_mutex);

    /**
     * Give each client its own thread so they're treated equally
     * and so that newly connected clients don't have to wait.
     * This scales very poorly, because block template creation is
     * slow, but is easier to reason about.
     *
     * A typical miner as well as a typical pool will only need one
     * connection. For the use case of a public facing template provider,
     * further changes are needed anyway e.g. for DoS resistance.
     */
    void ThreadSv2ClientHandler(size_t client_id) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex, !m_backend_mutex);

    /**
     * Triggered on interrupt signals to stop the main event loop in ThreadSv2Handler().
     * Interrupts pending waitNext() calls
     */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex, !m_backend_mutex);

    /**
     * Tear down of the template provider thread and any other necessary tear down.
     */
    void StopThreads();

    /**
     * Main handler for all received stratum v2 messages.
     */
    void ProcessSv2Message(const node::Sv2NetMsg& sv2_header, Sv2Client& client) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    // Only used for tests
    XOnlyPubKey m_authority_pubkey;

    void RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    void SubmitSolution(node::Sv2SubmitSolutionMsg solution) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    void InterruptTemplateWaits() EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex, !m_tp_mutex) override;

    /* Block templates that connected clients may be working on */
    BlockTemplateCache& GetBlockTemplates() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex) { return m_block_template_cache; }

private:

    /* Forget templates from before the last block, but with a few seconds margin. */
    void PruneBlockTemplateCache() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex);

    /** Serialize and write a block to disk asynchronously after a short delay, using the provided template. */
    void SaveBlockAsync(std::shared_ptr<BlockTemplate> block_template, bool submitted);

    /**
     * Sends the best NewTemplate and SetNewPrevHash to a client.
     *
     * The current implementation doesn't create templates for future empty
     * or speculative blocks. Despite that, we first send NewTemplate with
     * future_template set to true, followed by SetNewPrevHash. We do this
     * both when first connecting and when a new block is found.
     *
     * When the template is update to take newer mempool transactions into
     * account, we set future_template to false and don't send SetNewPrevHash.
     */
    [[nodiscard]] bool SendWork(Sv2Client& client, uint64_t template_id, BlockTemplate& block_template, bool future_template);

    /**
     * Drop templates held for the current backend generation.
     */
    void ClearTemplateCache(bool log_dropped_templates) EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex);

    /**
     * Wait for an active backend session.
     */
    std::shared_ptr<BackendSession> WaitForBackend() EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex);

    /**
     * Mark a backend session disconnected and clear state held for it.
     */
    void DisconnectBackend(const std::shared_ptr<BackendSession>& backend, const char* operation, const std::exception& exception)
        EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex, !m_tp_mutex);

    /**
     * Interrupt template waits on the active backend session.
     */
    void InterruptBackend() EXCLUSIVE_LOCKS_REQUIRED(!m_backend_mutex, !m_tp_mutex);

};

#endif // BITCOIN_SV2_TEMPLATE_PROVIDER_H
