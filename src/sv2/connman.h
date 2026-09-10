// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SV2_CONNMAN_H
#define BITCOIN_SV2_CONNMAN_H

#include <common/sockman.h>
#include <interfaces/mining.h>
#include <sv2/messages.h>
#include <sv2/transport.h>
#include <pubkey.h>

#include <atomic>
#include <threadsafety.h>
#include <utility>

struct Sv2Client
{
    /* Ephemeral identifier */
    size_t m_id;

    /**
     * Transport
     */
    std::unique_ptr<Sv2Transport> m_transport;

    Mutex cs_status;

    /**
     * Whether the client has confirmed the connection with a successful SetupConnection.
     */
    bool m_setup_connection_confirmed GUARDED_BY(cs_status) = false;

    /**
     * Whether the client is a candidate for disconnection. The client's socket will be
     * closed after all queued messages have been sent.
     */
    bool m_disconnect_flag GUARDED_BY(cs_status) = false;

    Mutex cs_send;

    /** Queue of messages to be sent */
    std::deque<Sv2NetMsg> m_send_messages GUARDED_BY(cs_send);

    /**
     * Whether the client has received CoinbaseOutputConstraints message.
     */
    bool m_coinbase_output_constraints_recv = false;

    /**
     * Specific additional coinbase tx output size required for the client.
     */
    unsigned int m_coinbase_tx_outputs_size;

    /**
     * Tracks the best template in the Template Provider m_block_template_cache map.
     * Not guaranteed to still exist.
    */
    uint64_t m_best_template_id = 0;

    /**
     * Incremented every time a CoinbaseOutputConstraints message is received.
     * Used by the client handler thread to detect if a template was built with stale constraints.
    */
    std::atomic<uint64_t> m_coinbase_constraints_generation{0};

    /**
     * Pointer to the active block template that the client handler thread is currently waiting on.
     * Guarded by cs_status to allow the connman thread to safely call interruptWait() on it.
    */
    std::shared_ptr<interfaces::BlockTemplate> m_current_block_template GUARDED_BY(cs_status);

    explicit Sv2Client(size_t id, std::unique_ptr<Sv2Transport> transport) :
                       m_id{id}, m_transport{std::move(transport)} {};

    bool IsFullyConnected() EXCLUSIVE_LOCKS_REQUIRED(cs_status)
    {
        return !m_disconnect_flag && m_setup_connection_confirmed;
    }

    Sv2Client(Sv2Client&) = delete;
    Sv2Client& operator=(const Sv2Client&) = delete;
};

/**
 * Interface for sv2 message handling
 */
class Sv2EventsInterface
{
public:
    /**
     * We received and successfully parsed a RequestTransactionData message.
     * Deal with it and respond with either RequestTransactionData.Success or
     * RequestTransactionData.Error.
     */
    virtual void RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg) = 0;

    /**
     * We received and successfully parsed a SubmitSolution message.
     */
    virtual void SubmitSolution(node::Sv2SubmitSolutionMsg solution) = 0;

    virtual ~Sv2EventsInterface() = default;
};

/** Handle inbound Stratum V2 Template Distribution Protocol connections. */
class Sv2Connman : SockMan
{
private:
    /** Interface to pass events up */
    Sv2EventsInterface* m_msgproc;

    /**
     * The Stratum V2 spec version supported by the server. The protocol remains
     * Stratum V2 regardless of this value.
     */
    const uint16_t m_protocol_version = 2;

    /**
     * Required and optional flags supported for Template Distribution Protocol
     * clients. The protocol currently does not define any.
     */
    const uint32_t m_supported_flags{0};

    /**
     * Low-half flags required by this Template Distribution Protocol server. The
     * protocol currently does not define any.
     */
    const uint32_t m_required_flags{0};

    CKey m_static_key;

    XOnlyPubKey m_authority_pubkey;

    std::optional<Sv2SignatureNoiseMessage> m_certificate;

    /**
     * A map of all connected stratum v2 clients.
     */
    using Clients = std::unordered_map<NodeId, std::shared_ptr<Sv2Client>>;
    Clients m_sv2_clients GUARDED_BY(m_clients_mutex);

    /**
     * Creates a socket and binds the port for new stratum v2 connections.
     */
    [[nodiscard]] bool Bind(std::string host, uint16_t port);

    void DisconnectFlagged() EXCLUSIVE_LOCKS_REQUIRED(m_clients_mutex);

    std::pair<size_t, bool> SendMessagesAsBytes(Sv2Client& client)
        EXCLUSIVE_LOCKS_REQUIRED(client.cs_send);

    /**
     * Create a `Sv2Client` object and add it to the `m_sv2_clients` member.
     * @param[in] node_id Id of the newly accepted connection.
     * @param[in] me The address and port at our side of the connection.
     * @param[in] them The address and port at the peer's side of the connection.
     * @retval true on success
     * @retval false on failure, meaning that the associated socket and node_id should be discarded
     */
    virtual bool EventNewConnectionAccepted(NodeId node_id,
                                            const CService& me,
                                            const CService& them)
                                            EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex) override;

    void EventReadyToSend(NodeId node_id, bool& cancel_recv) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex);

    virtual void EventGotData(Id id, std::span<const uint8_t> data) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex);

    virtual void EventGotEOF(NodeId node_id) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex);

    virtual void EventGotPermanentReadError(NodeId node_id, const std::string& errmsg) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex);

    virtual void EventIOLoopCompletedForAll() EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex) override;

    /**
     * Encrypt the header and message payload and send it.
     * @throws std::runtime_error if encrypting the message fails.
     */
    bool EncryptAndSendMessage(Sv2Client& client, node::Sv2NetMsg& net_msg);

    /**
     * A helper method to read and decrypt multiple Sv2NetMsgs.
     */
    std::vector<node::Sv2NetMsg> ReadAndDecryptSv2NetMsgs(Sv2Client& client, std::span<std::byte> buffer);

public:
    Sv2Connman(CKey static_key, XOnlyPubKey authority_pubkey, Sv2SignatureNoiseMessage certificate) :
               m_static_key(static_key), m_authority_pubkey(authority_pubkey), m_certificate(certificate) {};

    ~Sv2Connman();

    Mutex m_clients_mutex;

    /**
     * Starts the Stratum v2 server and thread.
     * returns false if port is unable to bind.
     */
    [[nodiscard]] bool Start(Sv2EventsInterface* msgproc, std::string host, uint16_t port);

    /**
     * Triggered on interrupt signals to stop the main event loop in ThreadSv2Handler().
     */
    void Interrupt();

    /**
     * Tear down of the connman thread and any other necessary tear down.
     */
    void StopThreads();

    /**
     * Main handler for all received stratum v2 messages.
     */
    void ProcessSv2Message(const node::Sv2NetMsg& sv2_header, Sv2Client& client);

    /**
     * Attempt to flush the send queue immediately, without waiting for the
     * socket layer to signal readiness. Falls back to the regular send path if
     * the socket would block.
     */
    void TryOptimisticSend(Sv2Client& client) EXCLUSIVE_LOCKS_REQUIRED(client.cs_send);

    std::shared_ptr<Sv2Client> GetClientById(NodeId node_id) const EXCLUSIVE_LOCKS_REQUIRED(m_clients_mutex);

    using Sv2ClientFn = std::function<void(Sv2Client&)>;
    /** Perform a function on each fully connected client. */
    void ForEachClient(const Sv2ClientFn& func) EXCLUSIVE_LOCKS_REQUIRED(!m_clients_mutex)
    {
        LOCK(m_clients_mutex);
        for (const auto& client : m_sv2_clients) {
            LOCK(client.second->cs_status);
            if (client.second->IsFullyConnected()) func(*client.second);
        }
    };

    /** Number of clients that are not marked for disconnection, used for tests. */
    size_t ConnectedClients() EXCLUSIVE_LOCKS_REQUIRED(m_clients_mutex)
    {
        return std::count_if(m_sv2_clients.begin(), m_sv2_clients.end(), [](const auto& c) {
            LOCK(c.second->cs_status);
            return !c.second->m_disconnect_flag;
        });
    }

    /** Number of clients with m_setup_connection_confirmed, used for tests. */
    size_t FullyConnectedClients() EXCLUSIVE_LOCKS_REQUIRED(m_clients_mutex)
    {
        return std::count_if(m_sv2_clients.begin(), m_sv2_clients.end(), [](const auto& c) {
            LOCK(c.second->cs_status);
            return c.second->IsFullyConnected();
        });
    }

};

#endif // BITCOIN_SV2_CONNMAN_H
