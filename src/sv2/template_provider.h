#ifndef BITCOIN_SV2_TEMPLATE_PROVIDER_H
#define BITCOIN_SV2_TEMPLATE_PROVIDER_H

#include <chrono>
#include <interfaces/mining.h>
#include <sv2/connman.h>
#include <sv2/messages.h>
#include <logging.h>
#include <net.h>
#include <util/sock.h>
#include <util/time.h>
#include <streams.h>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>

using interfaces::BlockTemplate;

class CBlock;

/**
 * Node versions, using the same scheme as Bitcoin Core's CLIENT_VERSION:
 * 10000 * major + 100 * minor + build.
 *
 * Versions can only be told apart by which methods their mining interface
 * has, so these are the oldest version that could be on the other end.
 */
//! Bitcoin Core v31.0, the oldest release we support
static constexpr int NODE_VERSION_31_0{310000};
//! Bitcoin Core v32.0 mining interface. The node may be newer.
static constexpr int NODE_VERSION_32_00{320000};

/**
 * ProposeTemplate requests per client that may wait for or undergo validation
 * at once. Further requests get ProposeTemplate.Error job-validation-unavailable.
 */
static constexpr size_t MAX_PROPOSALS_IN_FLIGHT{4};
/**
 * ProposeTemplate requests per client that may wait for
 * ProvideMissingTransactions.Success. Beyond this the oldest is forgotten.
 */
static constexpr size_t MAX_PENDING_PROPOSALS{8};
/** How long a ProposeTemplate request waits for ProvideMissingTransactions.Success. */
static constexpr std::chrono::seconds PENDING_PROPOSAL_TIMEOUT{30};

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
    * The Mining interface is used to build new valid blocks, get the best known
    * block hash and to check whether the node is still in IBD.
    */
    interfaces::Mining& m_mining;

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
     * Validates proposed templates, see ThreadSv2ProposalHandler().
     */
    std::thread m_thread_sv2_proposal_handler;

    /**
     * Signal for handling interrupts and stopping the template provider event loop.
     */
    std::atomic<bool> m_flag_interrupt_sv2{false};
    CThreadInterrupt m_interrupt_sv2;
    std::atomic<bool> m_backend_connected{true};

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
     * Version of the node we're connected to, as far as its mining interface
     * lets us tell versions apart.
     *
     * Determined by DetectNodeVersion() when the template provider starts, so
     * that time critical calls don't need a round trip to find out.
     */
    std::atomic<int> m_node_version{NODE_VERSION_31_0};

    /**
     * Set m_node_version by calling a mining interface method that Bitcoin
     * Core v31 does not have.
     */
    void DetectNodeVersion();

    /**
     * A cache that maps ids used in NewTemplate messages and its associated
     * <prevhash,block template>.
     */
    using BlockTemplateCache = std::map<uint64_t, std::pair<uint256, std::shared_ptr<BlockTemplate>>>;
    BlockTemplateCache m_block_template_cache GUARDED_BY(m_tp_mutex);

    /**
     * A ProposeTemplate request that passed the checks which need no node
     * call, until it is answered.
     */
    struct Proposal {
        size_t client_id;
        uint32_t request_id;
        uint32_t version;
        CTransactionRef coinbase;
        std::vector<Wtxid> wtxids;
        //! The transaction for each entry of wtxids, nullptr while unknown.
        std::vector<CTransactionRef> txs;
        //! When a request in m_pending_proposals is forgotten.
        std::chrono::seconds expires{0};
    };

    /**
     * Proposals waiting for or undergoing validation, in arrival order. The
     * front is the one ThreadSv2ProposalHandler() is working on.
     */
    std::deque<Proposal> m_proposal_queue GUARDED_BY(m_tp_mutex);

    /**
     * Proposals waiting for ProvideMissingTransactions.Success, by client id
     * and request id.
     */
    std::map<std::pair<size_t, uint32_t>, Proposal> m_pending_proposals GUARDED_BY(m_tp_mutex);

    /** Signals a new entry in m_proposal_queue. */
    std::condition_variable_any m_proposal_cv;

public:
    explicit Sv2TemplateProvider(interfaces::Mining& mining);

    ~Sv2TemplateProvider() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    Mutex m_tp_mutex;

    /**
     * Starts the template provider server and thread.
     * returns false if port is unable to bind.
     */
    [[nodiscard]] bool Start(const Sv2TemplateProviderOptions& options = {});

    /** Version of the node, as determined by DetectNodeVersion() */
    int GetNodeVersion() const { return m_node_version; }

    /**
     * The main thread for the template provider, contains an event loop handling
     * all tasks for the template provider.
     */
    void ThreadSv2Handler() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

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
    void ThreadSv2ClientHandler(size_t client_id) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    /**
     * Validates proposed templates one at a time, in arrival order across
     * clients, so that the node calls this takes don't stall the networking
     * thread. Replies are queued under the same locks SendWork() uses.
     */
    void ThreadSv2ProposalHandler() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    /**
     * Triggered on interrupt signals to stop the main event loop in ThreadSv2Handler().
     * Interrupts pending waitNext() calls.
     * Safe to call more than once.
     */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    /** Mark the backend disconnected and interrupt without making more backend calls. */
    void BackendDisconnected() EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

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

    /**
     * Runs the checks that need no node call and queues the request for
     * ThreadSv2ProposalHandler().
     */
    void ProposeTemplate(Sv2Client& client, node::Sv2ProposeTemplateMsg msg) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    /**
     * Fills in the transactions of a pending request and queues it for
     * ThreadSv2ProposalHandler().
     */
    void ProvideMissingTransactions(Sv2Client& client, node::Sv2ProvideMissingTransactionsSuccessMsg msg) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex) override;

    /* Block templates that connected clients may be working on */
    BlockTemplateCache& GetBlockTemplates() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex) { return m_block_template_cache; }

    /** Number of clients not flagged for disconnection, used for tests. */
    size_t ConnectedClientCount()
    {
        LOCK(m_connman->m_clients_mutex);
        return m_connman->ConnectedClients();
    }

private:

    /* Forget templates from before the last block, but with a few seconds margin. */
    void PruneBlockTemplateCache() EXCLUSIVE_LOCKS_REQUIRED(m_tp_mutex);

    /** Serialize and write a block to disk asynchronously after a short delay, using the provided template. */
    void SaveBlockAsync(std::shared_ptr<BlockTemplate> block_template, bool submitted);

    /** Queue a reply for a client that may have disconnected meanwhile. */
    void SendToClient(size_t client_id, const node::Sv2NetMsg& msg);

    void SendProposeTemplateError(size_t client_id, uint32_t request_id, const std::string& code, const std::string& details);

    /** Append to m_proposal_queue, unless the request id is in use or the client has too many in flight. */
    void QueueProposal(Proposal proposal) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

    /**
     * Fetch unknown transactions from the node and either ask the client for
     * the rest or have the node check the assembled block. Replies to the
     * client in every case.
     */
    void ValidateProposal(Proposal proposal) EXCLUSIVE_LOCKS_REQUIRED(!m_tp_mutex);

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

};

#endif // BITCOIN_SV2_TEMPLATE_PROVIDER_H
