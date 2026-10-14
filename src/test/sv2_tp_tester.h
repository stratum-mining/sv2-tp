// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_TP_TESTER_H
#define BITCOIN_TEST_SV2_TP_TESTER_H

#include <mp/util.h>
#include <sv2/messages.h>
#include <sv2/template_provider.h>
#include <test/sv2_mock_mining.h>
#include <test/util/net.h>
#include <util/sock.h>

#include <array>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

// Forward declarations
class Sv2Transport;
namespace mp { class EventLoop; }
namespace mp { class Connection; }
namespace interfaces { class Init; class Mining; }

struct MockInit;

//! Which version of the mining interface the simulated node has. Methods that
//! it does not have throw, like they do when the IPC layer finds that the
//! other side does not implement them.
enum class MockNodeVersion : uint8_t {
    //! Has getTransactionsByTxID() and submitSolution() with reason and debug.
    CURRENT,
    //! Bitcoin Core v31: has neither.
    V31,
};

class TPTester {
private:
    //! Per-peer connection state. Each simulated client has its own noise
    //! transport and socket pipes.
    struct Peer {
        std::unique_ptr<Sv2Transport> transport;
        std::shared_ptr<DynSock::Pipes> pipes;
    };
    std::vector<Peer> m_peers;
    Peer& GetPeer(size_t peer_id);

    std::shared_ptr<DynSock::Queue> m_tp_accepted_sockets{std::make_shared<DynSock::Queue>()};

    // IPC loopback components
    std::thread m_loop_thread;
    mp::EventLoop* m_loop{nullptr};
    std::unique_ptr<mp::Connection> m_server_connection;
    std::unique_ptr<MockInit> m_server_init;
    std::unique_ptr<interfaces::Init> m_client_init;
    std::array<mp::SocketId, 2> m_ipc_fds{mp::SocketError, mp::SocketError};

public:
    std::unique_ptr<Sv2TemplateProvider> m_tp; //!< Sv2TemplateProvider being tested
    Sv2TemplateProviderOptions m_tp_options{.is_test = true}; //! Options passed to the TP
    std::shared_ptr<MockState> m_state; // shared state between server and control
    std::shared_ptr<MockMining> m_mining_control; // local control handle
    std::unique_ptr<interfaces::Mining> m_mining_proxy; // IPC mining proxy

    TPTester();
    /** @param[in] version Mining interface version of the simulated node */
    explicit TPTester(Sv2TemplateProviderOptions opts, MockNodeVersion version = MockNodeVersion::CURRENT);
    ~TPTester();

    void SendPeerBytes(size_t peer_id = 0);
    size_t PeerReceiveBytes(size_t peer_id = 0, Sv2NetMsg* message = nullptr);
    /** Connect (or reconnect) peer and perform the noise handshake. */
    void handshake(size_t peer_id = 0);
    void receiveMessage(Sv2NetMsg& msg, size_t peer_id = 0);
    Sv2NetMsg SetupConnectionMsg();
    size_t GetBlockTemplateCount();

    /** Send SetupConnection and verify Success reply. */
    void SendSetupConnection(size_t peer_id = 0);
    /** Send CoinbaseOutputConstraints message. */
    void SendCoinbaseOutputConstraints(size_t peer_id = 0, uint32_t max_additional_size = 1);
    /** Receive a NewTemplate + SetNewPrevHash pair and verify sizes and matching IDs. Returns the template ID. */
    uint64_t ReceiveTemplatePair(size_t peer_id = 0);

    // SV2 message payload sizes used for test verification
    static constexpr size_t SV2_SET_NEW_PREV_HASH_MSG_SIZE =
        8 +                 // template_id
        32 +                // prev_hash
        4 +                 // ntime_start
        4 +                 // nBits
        32;                 // target
    static constexpr size_t SV2_NEW_TEMPLATE_MSG_SIZE =
        8 +                 // template_id
        1 +                 // future_template
        4 +                 // version
        4 +                 // coinbase_tx_version
        2 +                 // coinbase_prefix (CompactSize(1) + 1-byte OP_0)
        4 +                 // coinbase_tx_input_sequence
        8 +                 // coinbase_tx_value_remaining
        4 +                 // coinbase_tx_outputs_count
        2 + 56 +            // B0_64K: length prefix (2 bytes) + 2 outputs (witness commitment 43 bytes + merge mining 13 bytes)
        4 +                 // coinbase_tx_locktime
        1;                  // merkle_path count (CompactSize(0))
};

#endif // BITCOIN_TEST_SV2_TP_TESTER_H
