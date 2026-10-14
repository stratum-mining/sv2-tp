// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/sv2_tp_tester.h>

#include <boost/test/unit_test.hpp>
#include <interfaces/init.h>
#include <ipc/exception.h>
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

namespace {
//! Simulates a node without getTransactionsByTxID(), by throwing the same
//! exception the IPC layer raises for a method the other side does not
//! implement.
//!
//! The mock server can't do this, because it implements every method of the
//! current interface. Having it throw instead would not be the same thing: a
//! real Bitcoin Core v31 node does not throw, capnp just tells the client that
//! the method does not exist.
class OldNodeMining : public interfaces::Mining
{
public:
    explicit OldNodeMining(std::unique_ptr<interfaces::Mining> mining) : m_mining{std::move(mining)} {}

    bool isTestChain() override { return m_mining->isTestChain(); }
    bool isInitialBlockDownload() override { return m_mining->isInitialBlockDownload(); }
    std::optional<interfaces::BlockRef> getTip() override { return m_mining->getTip(); }
    std::optional<interfaces::BlockRef> waitTipChanged(uint256 current_tip, MillisecondsDouble timeout) override
    {
        return m_mining->waitTipChanged(current_tip, timeout);
    }
    std::unique_ptr<interfaces::BlockTemplate> createNewBlock(const node::BlockCreateOptions& options, bool cooldown) override
    {
        return m_mining->createNewBlock(options, cooldown);
    }
    void interrupt() override { m_mining->interrupt(); }
    bool checkBlock(const CBlock& block, const node::BlockCheckOptions& options, std::string& reason, std::string& debug) override
    {
        return m_mining->checkBlock(block, options, reason, debug);
    }
    bool submitBlock(const CBlock& block, std::string& reason, std::string& debug) override
    {
        return m_mining->submitBlock(block, reason, debug);
    }
    std::vector<CTransactionRef> getTransactionsByTxID(const std::vector<Txid>&) override
    {
        throw ipc::Exception("kj::Exception: remote exception: Method not implemented.");
    }

private:
    std::unique_ptr<interfaces::Mining> m_mining;
};

} // namespace

struct MockInit : public interfaces::Init {
    std::shared_ptr<MockState> state;
    explicit MockInit(std::shared_ptr<MockState> s) : state(std::move(s)) {}
    std::unique_ptr<interfaces::Mining> makeMining() override
    {
        return std::make_unique<MockMining>(state);
    }
};

TPTester::TPTester() : TPTester(Sv2TemplateProviderOptions{.is_test = true}) {}

TPTester::TPTester(Sv2TemplateProviderOptions opts, MockNodeVersion version)
    : m_tp_options{opts}, m_state{std::make_shared<MockState>()}, m_mining_control{std::make_shared<MockMining>(m_state)}
{
    // Start cap'n proto event loop on a background thread
    std::promise<mp::EventLoop*> loop_ready;
    m_loop_thread = std::thread([&] {
        // Mirror IpcLogFn(): an error reported by the IPC layer, such as a
        // method the other side does not implement, is thrown to the caller.
        auto log_fn = [](mp::LogMessage message) {
            if (G_TEST_LOG_FUN) G_TEST_LOG_FUN(message.message);
            if (message.level == mp::Log::Raise) throw ipc::Exception(message.message);
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
        mp::Stream server_stream{mp::MakeStream(*m_loop, m_ipc_fds[0])};
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
    m_client_init = mp::ConnectStream<ipc::capnp::messages::Init>(
        *m_loop,
        mp::MakeStream(*m_loop, m_ipc_fds[1]));
    BOOST_REQUIRE(m_client_init != nullptr);
    m_mining_proxy = m_client_init->makeMining();
    BOOST_REQUIRE(m_mining_proxy != nullptr);
    if (version == MockNodeVersion::V31) {
        m_mining_proxy = std::make_unique<OldNodeMining>(std::move(m_mining_proxy));
    }

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
    // Set the interrupt flag before unblocking waitNext(), so the handler
    // exits instead of issuing another IPC request during teardown.
    if (m_tp) {
        m_tp->RequestInterrupt();
    }

    // Signal the mock state directly (bypasses IPC) so that any
    // MockBlockTemplate::waitNext() blocked on the event-loop thread
    // returns immediately.
    m_mining_control->Shutdown();

    // Wait for the handler thread before releasing its IPC proxies.
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

        // Process pending release/disconnect messages, then destroy the server
        // connection on the event-loop thread before releasing the final loop ref.
        m_loop->sync([] {});
        m_loop->sync([this] { m_server_connection.reset(); });

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

TPTester::Peer& TPTester::GetPeer(size_t peer_id)
{
    BOOST_REQUIRE(peer_id < m_peers.size());
    return m_peers[peer_id];
}

void TPTester::SendPeerBytes(size_t peer_id)
{
    Peer& peer{GetPeer(peer_id)};
    const auto& [data, more, _m_message_type] = peer.transport->GetBytesToSend(/*have_next_message=*/false);
    BOOST_REQUIRE(data.size() > 0);

    // Schedule data to be returned by the next Recv() call from
    // Sv2Connman on the socket it has accepted.
    peer.pipes->recv.PushBytes(data.data(), data.size());
    peer.transport->MarkBytesSent(data.size());
}

/**
 * Drain bytes from the TP side until either:
 *  - The transport consumes them successfully (ReceivedBytes() returns true), or
 *  - We reach an optional minimum accumulation target (expected_min) AND ReceivedBytes() returns true, or
 *  - A timeout elapses (test failure).
 *
 * This removes brittleness where a single partial handshake/frame fragment caused an assertion failure.
 */
size_t TPTester::PeerReceiveBytes(size_t peer_id, Sv2NetMsg* message)
{
    Peer& peer{GetPeer(peer_id)};
    // Use shared fragment-tolerant helper for uniform instrumentation across tests.
    size_t consumed_total = 0;
    size_t total = Sv2TestAccumulateRecv(peer.pipes,
        [&peer, &consumed_total](std::span<const uint8_t> frag) {
            const size_t initial = frag.size();
            bool done = peer.transport->ReceivedBytes(frag);
            const size_t consumed = initial - frag.size();
            consumed_total += consumed;
            if (!frag.empty()) {
                peer.pipes->send.PushBytes(frag.data(), frag.size());
            }
            return done;
        }, std::chrono::milliseconds{2000}, "tp_peer_recv");
    if (total == Sv2HandshakeState::HANDSHAKE_STEP2_SIZE &&
        peer.transport &&
        peer.transport->GetSendState() != Sv2Transport::SendState::READY) {
        BOOST_FAIL("tp_peer_recv: full handshake bytes accumulated (" << total << ") but transport not READY (expected ReadMsgES success)");
    }

    if (message) BOOST_REQUIRE(peer.transport->ReceivedMessageComplete());
    if (peer.transport && peer.transport->ReceivedMessageComplete()) {
        bool reject_message = false;
        Sv2NetMsg received{peer.transport->GetReceivedMessage(std::chrono::microseconds{0}, reject_message)};
        BOOST_REQUIRE(!reject_message);
        if (message) *message = std::move(received);
    }
    return consumed_total > 0 ? consumed_total : total;
}

void TPTester::handshake(size_t peer_id)
{
    if (peer_id >= m_peers.size()) m_peers.resize(peer_id + 1);
    Peer& peer{m_peers[peer_id]};

    auto peer_static_key{GenerateRandomKey()};
    peer.transport = std::make_unique<Sv2Transport>(std::move(peer_static_key), m_tp->m_authority_pubkey);

    // Have Sv2Connman's listen socket's Accept() simulate a newly arrived connection.
    peer.pipes = std::make_shared<DynSock::Pipes>();
    m_tp_accepted_sockets->Push(
        std::make_unique<DynSock>(peer.pipes, std::make_shared<DynSock::Queue>()));

    // Flush transport for handshake part 1
    SendPeerBytes(peer_id);

    // Read handshake part 2 from transport. We no longer assume it arrives as one contiguous read;
    // PeerReceiveBytes will loop until the transport signals completion (READY send state) or timeout.
    size_t received = PeerReceiveBytes(peer_id);
    // Handshake step 2 is a fixed-size structure; assert strict equality.
    BOOST_REQUIRE_EQUAL(received, Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
}

void TPTester::receiveMessage(Sv2NetMsg& msg, size_t peer_id)
{
    // Client encrypts message and puts it on the transport:
    CSerializedNetMsg net_msg{std::move(msg)};
    BOOST_REQUIRE(GetPeer(peer_id).transport->SetMessageToSend(net_msg));
    SendPeerBytes(peer_id);
}

Sv2NetMsg TPTester::SetupConnectionMsg()
{
    std::vector<uint8_t> bytes{
        0x02,                                                 // protocol
        0x02, 0x00,                                           // min_version
        0x02, 0x00,                                           // max_version
        0x00, 0x00, 0x00, 0x00,                               // flags
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

void TPTester::SendSetupConnection(size_t peer_id)
{
    node::Sv2NetMsg setup{SetupConnectionMsg()};
    receiveMessage(setup, peer_id);
    // SetupConnection.Success is 6 bytes
    BOOST_REQUIRE_EQUAL(PeerReceiveBytes(peer_id), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);
}

void TPTester::SendCoinbaseOutputConstraints(size_t peer_id, uint32_t max_additional_size)
{
    std::vector<uint8_t> coinbase_output_constraint_bytes{
        uint8_t(max_additional_size), uint8_t(max_additional_size >> 8),
        uint8_t(max_additional_size >> 16), uint8_t(max_additional_size >> 24), // coinbase_output_max_additional_size
        0x00, 0x00                                                                // coinbase_output_max_sigops
    };
    node::Sv2NetMsg coc_msg{node::Sv2MsgType::COINBASE_OUTPUT_CONSTRAINTS, std::move(coinbase_output_constraint_bytes)};
    receiveMessage(coc_msg, peer_id);
}

uint64_t TPTester::ReceiveTemplatePair(size_t peer_id)
{
    Sv2NetMsg new_template{node::Sv2MsgType::NEW_TEMPLATE, {}};
    BOOST_REQUIRE_EQUAL(PeerReceiveBytes(peer_id, &new_template), SV2_HEADER_ENCRYPTED_SIZE + SV2_NEW_TEMPLATE_MSG_SIZE + Poly1305::TAGLEN);
    BOOST_REQUIRE(new_template.m_msg_type == node::Sv2MsgType::NEW_TEMPLATE);
    DataStream template_stream{MakeByteSpan(new_template.m_msg)};
    uint64_t template_id;
    bool future_template;
    template_stream >> template_id >> future_template;
    BOOST_REQUIRE(future_template);

    Sv2NetMsg new_prev_hash{node::Sv2MsgType::SET_NEW_PREV_HASH, {}};
    BOOST_REQUIRE_EQUAL(PeerReceiveBytes(peer_id, &new_prev_hash), SV2_HEADER_ENCRYPTED_SIZE + SV2_SET_NEW_PREV_HASH_MSG_SIZE + Poly1305::TAGLEN);
    BOOST_REQUIRE(new_prev_hash.m_msg_type == node::Sv2MsgType::SET_NEW_PREV_HASH);
    DataStream prev_hash_stream{MakeByteSpan(new_prev_hash.m_msg)};
    uint64_t prev_hash_template_id;
    prev_hash_stream >> prev_hash_template_id;
    BOOST_REQUIRE_EQUAL(prev_hash_template_id, template_id);
    return template_id;
}
