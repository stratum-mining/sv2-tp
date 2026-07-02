#ifndef BITCOIN_TEST_SV2_CONNMAN_TESTER_H
#define BITCOIN_TEST_SV2_CONNMAN_TESTER_H

#include <sv2/connman.h>
#include <sv2/messages.h>
#include <sv2/transport.h>
#include <test/util/net.h>

#include <memory>

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

    ConnTester();
    ~ConnTester();

    void RemoteToLocalBytes();
    size_t LocalToRemoteBytes();
    void handshake();
    void RemoteToLocalMsg(Sv2NetMsg& msg);
    bool IsConnected();
    bool IsFullyConnected();
    Sv2NetMsg SetupConnectionMsg();

    void RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg) override;
    void SubmitSolution(node::Sv2SubmitSolutionMsg solution) override;
    void InterruptTemplateWaits() override {}
};

#endif // BITCOIN_TEST_SV2_CONNMAN_TESTER_H
