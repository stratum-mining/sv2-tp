#include <test/sv2_connman_tester.h>

#include <boost/test/unit_test.hpp>
#include <test/sv2_handshake_test_util.h>
#include <test/sv2_test_setup.h>
#include <util/sock.h>

ConnTester::ConnTester()
{
    CreateSock = [this](int, int, int) -> std::unique_ptr<Sock> {
        // This will be the bind/listen socket from m_connman. It will
        // create other sockets via its Accept() method.
        return std::make_unique<DynSock>(std::make_shared<DynSock::Pipes>(), m_sv2connman_accepted_sockets);
    };

    CKey static_key;
    static_key.MakeNewKey(true);
    auto authority_key{GenerateRandomKey()};
    m_connman_authority_pubkey = XOnlyPubKey(authority_key.GetPubKey());

    // Generate and sign certificate
    uint32_t now_secs{0};
    uint32_t valid_from{0};
    uint32_t valid_to{0};
    Sv2SignatureNoiseMessage certificate = MakeSkewTolerantCertificate(static_key, authority_key, now_secs, valid_from, valid_to);

    m_connman = std::make_unique<Sv2Connman>(static_key, m_connman_authority_pubkey, certificate);

    BOOST_REQUIRE(m_connman->Start(this, "127.0.0.1", 18447));
}

ConnTester::~ConnTester()
{
    CreateSock = CreateSockOS;
}

void ConnTester::RemoteToLocalBytes()
{
    const auto& [data, more, _m_message_type] = m_remote_transport->GetBytesToSend(/*have_next_message=*/false);
    BOOST_REQUIRE(data.size() > 0);
    // Schedule data to be returned by the next Recv() call from
    // Sv2Connman on the socket it has accepted.
    m_current_client_pipes->recv.PushBytes(data.data(), data.size());
    m_remote_transport->MarkBytesSent(data.size());
}

size_t ConnTester::LocalToRemoteBytes()
{
    // Unified fragment-tolerant receive for test bytes from Sv2Connman -> remote peer.
    // allow_zero_first=true so callers can detect immediate disconnects (returns 0) without failure.
    return Sv2TestAccumulateRecv(m_current_client_pipes,
        [this](std::span<const uint8_t> frag) { return m_remote_transport->ReceivedBytes(frag); },
        std::chrono::milliseconds{1000}, "connman_local_to_remote", /*allow_zero_first=*/true);
}

std::pair<Sv2NetMsg, size_t> ConnTester::LocalToRemoteMsg()
{
    const size_t bytes{LocalToRemoteBytes()};
    BOOST_REQUIRE(m_remote_transport->ReceivedMessageComplete());
    bool reject_message{false};
    CNetMessage net_msg{m_remote_transport->GetReceivedMessage(std::chrono::microseconds{0}, reject_message)};
    BOOST_REQUIRE(!reject_message);
    return {Sv2NetMsg{std::move(net_msg)}, bytes};
}

/* Create a new client and perform handshake */
void ConnTester::handshake()
{
    m_remote_transport.reset();

    auto peer_static_key{GenerateRandomKey()};
    m_remote_transport = std::make_unique<Sv2Transport>(std::move(peer_static_key), m_connman_authority_pubkey);

    // Have Sv2Connman's listen socket's Accept() simulate a newly arrived connection.
    m_current_client_pipes = std::make_shared<DynSock::Pipes>();
    m_sv2connman_accepted_sockets->Push(
        std::make_unique<DynSock>(m_current_client_pipes, std::make_shared<DynSock::Queue>()));

    // Flush transport for handshake part 1
    RemoteToLocalBytes();

    // Read handshake part 2 from transport using fragment-tolerant helper.
    // The handshake may arrive in multiple fragments; accumulate until ReceivedBytes returns true.
    size_t received = Sv2TestAccumulateRecv(m_current_client_pipes,
        [this](std::span<const uint8_t> frag) {
            return m_remote_transport->ReceivedBytes(frag);
        }, std::chrono::milliseconds{2000}, "connman_handshake2");

    // Enforce exact size of handshake step 2.
    BOOST_REQUIRE_EQUAL(received, Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
    if (received == Sv2HandshakeState::HANDSHAKE_STEP2_SIZE &&
        m_remote_transport &&
        m_remote_transport->GetSendState() != Sv2Transport::SendState::READY) {
        BOOST_FAIL("connman_handshake2: full handshake bytes accumulated (" << received << ") but transport not READY (expected ReadMsgES success)");
    }

    BOOST_REQUIRE(IsConnected());
}

void ConnTester::RemoteToLocalMsg(Sv2NetMsg& msg)
{
    // Client encrypts message and puts it on the transport:
    CSerializedNetMsg net_msg{std::move(msg)};
    BOOST_REQUIRE(m_remote_transport->SetMessageToSend(net_msg));
    RemoteToLocalBytes();
}

bool ConnTester::IsConnected()
{
    LOCK(m_connman->m_clients_mutex);
    return m_connman->ConnectedClients() > 0;
}

bool ConnTester::IsFullyConnected()
{
    LOCK(m_connman->m_clients_mutex);
    return m_connman->FullyConnectedClients() > 0;
}

Sv2NetMsg ConnTester::SetupConnectionMsg(uint8_t protocol, uint16_t min_version,
                                         uint16_t max_version, uint32_t flags)
{
    DataStream ss{};
    ss << protocol
       << min_version
       << max_version
       << flags
       << std::string{"0.0.0.0"}
       << uint16_t{8545}
       << std::string{"Bitmain"}
       << std::string{"S9i 13.5"}
       << std::string{"braiins-os-2018-09-22-1-hash"}
       << std::string{"some-device-uuid"};

    std::vector<uint8_t> bytes(ss.size());
    ss >> MakeWritableByteSpan(bytes);

    return node::Sv2NetMsg{node::Sv2MsgType::SETUP_CONNECTION, std::move(bytes)};
}

void ConnTester::RequestTransactionData(Sv2Client& client, node::Sv2RequestTransactionDataMsg msg)
{
    BOOST_TEST_MESSAGE("Process RequestTransactionData");
}

void ConnTester::SubmitSolution(node::Sv2SubmitSolutionMsg solution)
{
    BOOST_TEST_MESSAGE("Process SubmitSolution");
}
