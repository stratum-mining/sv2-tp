// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_SV2_TP_TESTER_H
#define BITCOIN_TEST_SV2_TP_TESTER_H

#include <sv2/template_provider.h>
#include <sv2/messages.h>
#include <test/util/net.h>
#include <util/sock.h>

#include <memory>
#include <thread>

// Forward declarations
class Sv2Transport;
namespace mp { class EventLoop; }
namespace interfaces { class Init; class Mining; }

struct MockState;
class MockMining;

class TPTester {
private:
    std::unique_ptr<Sv2Transport> m_peer_transport; //!< Transport for peer
    std::shared_ptr<DynSock::Queue> m_tp_accepted_sockets{std::make_shared<DynSock::Queue>()};
    std::shared_ptr<DynSock::Pipes> m_current_client_pipes;

    // IPC loopback components
    std::thread m_loop_thread;
    mp::EventLoop* m_loop{nullptr};
    std::unique_ptr<interfaces::Init> m_server_init;
    std::unique_ptr<interfaces::Init> m_client_init;
    int m_ipc_fds[2]{-1, -1};

public:
    std::unique_ptr<Sv2TemplateProvider> m_tp; //!< Sv2TemplateProvider being tested
    Sv2TemplateProviderOptions m_tp_options{.is_test = true}; //! Options passed to the TP
    std::shared_ptr<MockState> m_state; // shared state between server and control
    std::shared_ptr<MockMining> m_mining_control; // local control handle
    std::unique_ptr<interfaces::Mining> m_mining_proxy; // IPC mining proxy

    TPTester();
    explicit TPTester(Sv2TemplateProviderOptions opts);
    ~TPTester();

    void SendPeerBytes();
    size_t PeerReceiveBytes();
    void handshake();
    void receiveMessage(Sv2NetMsg& msg);
    Sv2NetMsg SetupConnectionMsg();
    size_t GetBlockTemplateCount();
};

#endif // BITCOIN_TEST_SV2_TP_TESTER_H
