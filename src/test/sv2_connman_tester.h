#ifndef BITCOIN_TEST_SV2_CONNMAN_TESTER_H
#define BITCOIN_TEST_SV2_CONNMAN_TESTER_H

#include <sv2/connman.h>
#include <sv2/messages.h>
#include <sv2/transport.h>
#include <test/util/net.h>

#include <atomic>
#include <memory>
#include <utility>

/**
  * A class for testing the Sv2Connman. Each ConnTester encapsulates a
  * Sv2Connman (the one being tested) as well as a Sv2Cipher
  * to act as the other side.
  */
class ConnTester : Sv2EventsInterface
{
private:
    std::unique_ptr<Sv2Transport> m_remote_transport; //!< Transport for peer
    // Sockets that will be returned by the Sv2Connman's listening socket Accept() method.
    std::shared_ptr<DynSock::Queue> m_sv2connman_accepted_sockets{std::make_shared<DynSock::Queue>()};

    std::shared_ptr<DynSock::Pipes> m_current_client_pipes;

    XOnlyPubKey m_connman_authority_pubkey;

public:
    std::unique_ptr<Sv2Connman> m_connman; //!< Sv2Connman being tested
    std::atomic<size_t> m_submit_solution_count{0}; //!< Number of SubmitSolution messages forwarded to us
    std::atomic<size_t> m_request_transaction_data_count{0}; //!< Number of RequestTransactionData messages forwarded to us
    std::atomic<size_t> m_propose_template_count{0}; //!< Number of ProposeTemplate messages forwarded to us
    std::atomic<size_t> m_provide_missing_transactions_count{0}; //!< Number of ProvideMissingTransactions.Success messages forwarded to us

    /** @param[in] supported_flags SetupConnection flags the connman accepts */
    explicit ConnTester(uint32_t supported_flags = 0);
    ~ConnTester();

    void RemoteToLocalBytes();
    size_t LocalToRemoteBytes();
    /** Retrieve the message completed by LocalToRemoteBytes(). */
    Sv2NetMsg GetReceivedMessage();
    std::pair<Sv2NetMsg, size_t> LocalToRemoteMsg();
    void handshake();
    void RemoteToLocalMsg(Sv2NetMsg& msg);
    bool IsConnected();
    bool IsFullyConnected();
    Sv2NetMsg SetupConnectionMsg(uint8_t protocol = node::TEMPLATE_DISTRIBUTION_PROTOCOL,
                                 uint16_t min_version = 2,
                                 uint16_t max_version = 2,
                                 uint32_t flags = 0);
    /** Wait until a message counter reaches count. */
    bool WaitForCount(const std::atomic<size_t>& counter, size_t count);

    void RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg) override;
    void SubmitSolution(node::Sv2SubmitSolutionMsg solution) override;
    void ProposeTemplate(Sv2Client& client, node::Sv2ProposeTemplateMsg msg) override;
    void ProvideMissingTransactions(Sv2Client& client, node::Sv2ProvideMissingTransactionsSuccessMsg msg) override;
};

#endif // BITCOIN_TEST_SV2_CONNMAN_TESTER_H
