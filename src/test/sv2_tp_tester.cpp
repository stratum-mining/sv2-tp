// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_tp_tester.h>

#include <boost/test/unit_test.hpp>
#include <interfaces/init.h>
#include <mp/proxy-io.h>
#include <mp/util.h>
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
#include <test/sv2_handshake_test_util.h>

#include <future>

struct MockInit : public interfaces::Init {
    std::shared_ptr<MockState> state;
    explicit MockInit(std::shared_ptr<MockState> s) : state(std::move(s)) {}
    std::unique_ptr<interfaces::Mining> makeMining() override
    {
        return std::make_unique<MockMining>(state);
    }
};

TPTester::TPTester() : TPTester(Sv2TemplateProviderOptions{.is_test = true}) {}

TPTester::TPTester(Sv2TemplateProviderOptions opts)
    : m_tp_options{opts}, m_state{std::make_shared<MockState>()}, m_mining_control{std::make_shared<MockMining>(m_state)}
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
    m_ipc_fds = mp::SocketPair();

    // Create server Init exposing MockMining via shared state
    m_server_init = std::make_unique<MockInit>(m_state);
    MockInit& server_init = *m_server_init;
    // Register server side on the event loop thread
    m_loop->sync([&] {
        mp::Stream server_stream{m_loop->m_io_context.lowLevelProvider->wrapSocketFd(m_ipc_fds[0], kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP)};
        m_server_connection = std::make_unique<mp::Connection>(
            *m_loop,
            std::move(server_stream),
            [&server_init](mp::Connection& connection) {
                auto server_proxy = kj::heap<mp::ProxyServer<ipc::capnp::messages::Init>>(
                    std::shared_ptr<MockInit>(&server_init, [](MockInit*) {}), connection);
                return capnp::Capability::Client(kj::mv(server_proxy));
            });
        m_server_connection->onDisconnect([this] { m_server_connection.reset(); });
    });

    // Connect client side and fetch Mining proxy
    mp::Stream client_stream{m_loop->m_io_context.lowLevelProvider->wrapSocketFd(m_ipc_fds[1], kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP)};
    m_client_init = mp::ConnectStream<ipc::capnp::messages::Init>(*m_loop, std::move(client_stream));
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
    // Set the interrupt flag directly (atomic, no IPC needed) so the
    // client thread exits its main loop after the current waitNext()
    // returns. This MUST happen before Shutdown() below, otherwise
    // the client thread spins in a tight IPC waitNext() loop that
    // starves the destructor's own IPC calls on Windows.
    if (m_tp) {
        m_tp->RequestInterrupt();
    }

    // Signal the mock state directly (bypasses IPC) so that any
    // MockBlockTemplate::waitNext() blocked on the event-loop thread
    // returns immediately.
    m_mining_control->Shutdown();

    // Now that the flag is set and waitNext() will return, the client
    // thread will see m_flag_interrupt_sv2 and exit. Connman interrupt
    // + stop ensures the socket handler thread also winds down.
    if (m_tp) {
        m_tp->Interrupt();
        m_tp->StopThreads();
    }

    // Hold a loop ref while tearing down dependent objects to keep loop alive.
    if (m_loop) {
        mp::EventLoopRef loop_ref{*m_loop};
        m_tp.reset();
        m_mining_proxy.reset();
        m_client_init.reset();

        // Pump the loop once so pending release/disconnect messages are
        // processed, then explicitly tear down the server-side Connection.
        // This avoids depending on Windows socketpair disconnect behavior to
        // release the final EventLoopRef and let the loop thread exit.
        m_loop->sync([] {});
        if (m_server_connection) {
            m_loop->sync([this] { m_server_connection.reset(); });
        }

        m_server_init.reset();
    } else {
        m_server_connection.reset();
        m_tp.reset();
        m_mining_proxy.reset();
        m_client_init.reset();
        m_server_init.reset();
    }
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

/**
 * Drain bytes from the TP side until either:
 *  - The transport consumes them successfully (ReceivedBytes() returns true), or
 *  - We reach an optional minimum accumulation target (expected_min) AND ReceivedBytes() returns true, or
 *  - A timeout elapses (test failure).
 *
 * This removes brittleness where a single partial handshake/frame fragment caused an assertion failure.
 */
size_t TPTester::PeerReceiveBytes()
{
    // Use shared fragment-tolerant helper for uniform instrumentation across tests.
    size_t consumed_total = 0;
    size_t total = Sv2TestAccumulateRecv(m_current_client_pipes,
        [this, &consumed_total](std::span<const uint8_t> frag) {
            const size_t initial = frag.size();
            bool done = m_peer_transport->ReceivedBytes(frag);
            const size_t consumed = initial - frag.size();
            consumed_total += consumed;
            if (!frag.empty()) {
                m_current_client_pipes->send.PushBytes(frag.data(), frag.size());
            }
            return done;
        }, std::chrono::milliseconds{2000}, "tp_peer_recv");
    if (total == Sv2HandshakeState::HANDSHAKE_STEP2_SIZE &&
        m_peer_transport &&
        m_peer_transport->GetSendState() != Sv2Transport::SendState::READY) {
        BOOST_FAIL("tp_peer_recv: full handshake bytes accumulated (" << total << ") but transport not READY (expected ReadMsgES success)");
    }

    if (m_peer_transport && m_peer_transport->ReceivedMessageComplete()) {
        bool reject_message = false;
        m_peer_transport->GetReceivedMessage(std::chrono::microseconds{0}, reject_message);
        BOOST_REQUIRE(!reject_message);
    }
    return consumed_total > 0 ? consumed_total : total;
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

    // Read handshake part 2 from transport. We no longer assume it arrives as one contiguous read;
    // PeerReceiveBytes will loop until the transport signals completion (READY send state) or timeout.
    size_t received = PeerReceiveBytes();
    // Handshake step 2 is a fixed-size structure; assert strict equality.
    BOOST_REQUIRE_EQUAL(received, Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
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

void TPTester::SendSetupConnection()
{
    node::Sv2NetMsg setup{SetupConnectionMsg()};
    receiveMessage(setup);
    // SetupConnection.Success is 6 bytes
    BOOST_REQUIRE_EQUAL(PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
}

void TPTester::SendCoinbaseOutputConstraints()
{
    std::vector<uint8_t> coinbase_output_constraint_bytes{
        0x01, 0x00, 0x00, 0x00, // coinbase_output_max_additional_size
        0x00, 0x00              // coinbase_output_max_sigops
    };
    node::Sv2NetMsg coc_msg{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_constraint_bytes)};
    receiveMessage(coc_msg);
}

size_t TPTester::ReceiveTemplatePair()
{
    const size_t expected_set_new_prev_hash = SV2_HEADER_ENCRYPTED_SIZE + SV2_SET_NEW_PREV_HASH_MSG_SIZE + Poly1305::TAGLEN;
    const size_t expected_new_template = SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MSG_SIZE + Poly1305::TAGLEN;
    const size_t expected_pair_bytes = expected_set_new_prev_hash + expected_new_template;

    size_t accumulated = 0;
    bool seen_prev_hash = false;
    bool seen_new_template = false;
    int iterations = 0;

    while (accumulated < expected_pair_bytes) {
        size_t chunk = PeerReceiveBytes();
        accumulated += chunk;
        ++iterations;

        if (chunk == expected_set_new_prev_hash) {
            seen_prev_hash = true;
        } else if (chunk == expected_new_template) {
            seen_new_template = true;
        } else if (chunk == expected_pair_bytes) {
            seen_prev_hash = true;
            seen_new_template = true;
            break;
        } else {
            BOOST_FAIL("Unexpected message size in template pair");
        }

        BOOST_REQUIRE_MESSAGE(iterations <= 2, "Too many fragments in template pair");
    }

    BOOST_REQUIRE_MESSAGE(seen_prev_hash, "Missing SetNewPrevHash in template pair");
    BOOST_REQUIRE_MESSAGE(seen_new_template, "Missing NewTemplate in template pair");
    BOOST_REQUIRE_EQUAL(accumulated, expected_pair_bytes);
    return accumulated;
}
