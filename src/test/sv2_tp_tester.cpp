// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_tp_tester.h>

#include <boost/test/unit_test.hpp>
#include <interfaces/init.h>
#include <mp/proxy-io.h>
#include <src/ipc/capnp/init.capnp.h>
#include <src/ipc/capnp/init.capnp.proxy.h>
#include <sv2/messages.h>
#include <sv2/template_provider.h>
#include <sync.h>
#include <test/util/net.h>
#include <util/translation.h>

// Forward-declare the test logging callback provided by main.cpp
extern std::function<void(const std::string&)> G_TEST_LOG_FUN;

#include <test/sv2_mock_mining.h>

#include <future>
#include <sys/socket.h>
#include <unistd.h>

namespace {
struct MockInit : public interfaces::Init {
    std::shared_ptr<MockState> state;
    explicit MockInit(std::shared_ptr<MockState> s) : state(std::move(s)) {}
    std::unique_ptr<interfaces::Mining> makeMining() override
    {
        return std::make_unique<MockMining>(state);
    }
};
} // namespace

TPTester::TPTester()
    : m_state{std::make_shared<MockState>()}, m_mining_control{std::make_shared<MockMining>(m_state)}
{
    // Start cap'n proto event loop on a background thread
    std::promise<mp::EventLoop*> loop_ready;
    m_loop_thread = std::thread([&] {
        auto log_fn = [](bool /*raise*/, std::string message) {
            if (G_TEST_LOG_FUN) G_TEST_LOG_FUN(message);
        };
        mp::EventLoop loop("sv2-tp-test", log_fn);
        m_loop = &loop;
        loop_ready.set_value(m_loop);
        loop.loop();
    });
    loop_ready.get_future().wait();

    // Create socketpair for in-process IPC stream
    int fds[2];
    int rc = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    BOOST_REQUIRE_EQUAL(rc, 0);
    m_ipc_fds[0] = fds[0];
    m_ipc_fds[1] = fds[1];

    // Create server Init exposing MockMining via shared state
    m_server_init = std::make_unique<MockInit>(m_state);
    // Register server side on the event loop thread
    m_loop->sync([&] {
        mp::ServeStream<ipc::capnp::messages::Init>(*m_loop, m_ipc_fds[0], *static_cast<MockInit*>(m_server_init.get()));
    });

    // Connect client side and fetch Mining proxy
    m_client_init = mp::ConnectStream<ipc::capnp::messages::Init>(*m_loop, m_ipc_fds[1]);
    BOOST_REQUIRE(m_client_init != nullptr);
    m_mining_proxy = m_client_init->makeMining();
    BOOST_REQUIRE(m_mining_proxy != nullptr);

    // Construct Template Provider with the IPC-backed Mining proxy
    m_tp = std::make_unique<Sv2TemplateProvider>(*m_mining_proxy);

    CreateSock = [this](int, int, int) -> std::unique_ptr<Sock> {
        // This will be the bind/listen socket from m_tp. It will
        // create other sockets via its Accept() method.
        return std::make_unique<DynSock>(std::make_shared<DynSock::Pipes>(), m_tp_accepted_sockets);
    };

    BOOST_REQUIRE(m_tp->Start(m_tp_options));
}

TPTester::~TPTester()
{
    // Ensure TP shuts down before tearing down IPC
    m_tp.reset();
    // Drop client proxies first
    m_mining_proxy.reset();
    m_client_init.reset();
    // Ask event loop to drop all incoming connections now. This will
    // close streams on the loop thread and let the loop exit cleanly.
    if (m_loop) {
        m_loop->sync([&] { m_loop->m_incoming_connections.clear(); });
        // Brief loop tick to allow any pending RPC shutdown tasks to run
        m_loop->sync([&] {});
    }
    // Mark FDs invalid to avoid accidental double-close (they are
    // owned by the connections cleared above).
    m_ipc_fds[0] = -1;
    m_ipc_fds[1] = -1;
    // Wait for event loop to exit (exits when no clients remain)
    if (m_loop_thread.joinable()) m_loop_thread.join();
}

void TPTester::SendPeerBytes()
{
    const auto& [data, more, _m_message_type] = m_peer_transport->GetBytesToSend(/*have_next_message=*/false);
    BOOST_REQUIRE(data.size() > 0);

    // Schedule data to be returned by the next Recv() call from
    // Sv2Connman on the socket it has accepted.
    m_current_client_pipes->recv.PushBytes(data.data(), data.size());
    m_peer_transport->MarkBytesSent(data.size());
}

size_t TPTester::PeerReceiveBytes()
{
    uint8_t buf[0x10000];
    // Get the data that has been written to the accepted socket with Send() by TP.
    // Wait until the bytes appear in the "send" pipe.
    ssize_t n;
    for (;;) {
        n = m_current_client_pipes->send.GetBytes(buf, sizeof(buf), 0);
        if (n != -1 || errno != EAGAIN) {
            break;
        }
        UninterruptibleSleep(50ms);
    }

    // Inform client's transport that some bytes have been received (sent by TP).
    if (n > 0) {
        std::span<const uint8_t> s(buf, n);
        BOOST_REQUIRE(m_peer_transport->ReceivedBytes(s));
    }

    return n;
}

void TPTester::handshake()
{
    m_peer_transport.reset();

    auto peer_static_key{GenerateRandomKey()};
    m_peer_transport = std::make_unique<Sv2Transport>(std::move(peer_static_key), m_tp->m_authority_pubkey);

    // Have Sv2Connman's listen socket's Accept() simulate a newly arrived connection.
    m_current_client_pipes = std::make_shared<DynSock::Pipes>();
    m_tp_accepted_sockets->Push(
        std::make_unique<DynSock>(m_current_client_pipes, std::make_shared<DynSock::Queue>()));

    // Flush transport for handshake part 1
    SendPeerBytes();

    // Read handshake part 2 from transport
    BOOST_REQUIRE_EQUAL(PeerReceiveBytes(), Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
}

void TPTester::receiveMessage(Sv2NetMsg& msg)
{
    // Client encrypts message and puts it on the transport:
    CSerializedNetMsg net_msg{std::move(msg)};
    BOOST_REQUIRE(m_peer_transport->SetMessageToSend(net_msg));
    SendPeerBytes();
}

Sv2NetMsg TPTester::SetupConnectionMsg()
{
    std::vector<uint8_t> bytes{
        0x02,                                                 // protocol
        0x02, 0x00,                                           // min_version
        0x02, 0x00,                                           // max_version
        0x01, 0x00, 0x00, 0x00,                               // flags
        0x07, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30,       // endpoint_host
        0x61, 0x21,                                           // endpoint_port
        0x07, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x69, 0x6e,       // vendor
        0x08, 0x53, 0x39, 0x69, 0x20, 0x31, 0x33, 0x2e, 0x35, // hardware_version
        0x1c, 0x62, 0x72, 0x61, 0x69, 0x69, 0x6e, 0x73, 0x2d, 0x6f, 0x73, 0x2d, 0x32, 0x30,
        0x31, 0x38, 0x2d, 0x30, 0x39, 0x2d, 0x32, 0x32, 0x2d, 0x31, 0x2d, 0x68, 0x61, 0x73,
        0x68, // firmware
        0x10, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
        0x75, 0x69, 0x64, // device_id
    };

    return node::Sv2NetMsg{node::Sv2MsgType::SETUP_CONNECTION, std::move(bytes)};
}

size_t TPTester::GetBlockTemplateCount()
{
    LOCK(m_tp->m_tp_mutex);
    return m_tp->GetBlockTemplates().size();
}
