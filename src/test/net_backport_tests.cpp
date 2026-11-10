// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/system.h>
#include <compat/compat.h>
#include <netbase.h>
#include <util/sock.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>

using namespace std::chrono_literals;

namespace {
class TestSock : public Sock
{
public:
    using Sock::Sock;
    using Sock::operator=;
    SOCKET Get() const { return m_socket; }
};

struct TcpPair {
    std::shared_ptr<TestSock> client;
    std::shared_ptr<TestSock> server;

    TcpPair()
    {
        static const bool networking{SetupNetworking()};
        BOOST_REQUIRE(networking);
        TestSock listener{static_cast<SOCKET>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))};
        BOOST_REQUIRE(!(listener == INVALID_SOCKET));
        BOOST_REQUIRE(listener.IsSelectable());
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(listener.Bind(reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
        BOOST_REQUIRE_EQUAL(listener.Listen(1), 0);
        socklen_t size{sizeof(address)};
        BOOST_REQUIRE_EQUAL(listener.GetSockName(reinterpret_cast<sockaddr*>(&address), &size), 0);
        client = std::make_shared<TestSock>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        BOOST_REQUIRE(!(*client == INVALID_SOCKET));
        BOOST_REQUIRE(client->IsSelectable());
        BOOST_REQUIRE_EQUAL(client->Connect(reinterpret_cast<sockaddr*>(&address), size), 0);
        server = std::make_shared<TestSock>(accept(listener.Get(), nullptr, nullptr));
        BOOST_REQUIRE(!(*server == INVALID_SOCKET));
        BOOST_REQUIRE(server->IsSelectable());
        BOOST_REQUIRE(server->SetNonBlocking());
    }
};
} // namespace

BOOST_AUTO_TEST_SUITE(net_backport_tests)

BOOST_AUTO_TEST_CASE(ipv6_documentation_range)
{
    for (const char* address : {"3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"}) {
        const auto ip{LookupHost(address, /*fAllowLookup=*/false)};
        BOOST_REQUIRE(ip);
        BOOST_CHECK(!ip->IsValid());
        BOOST_CHECK(!ip->IsRoutable());
    }
    for (const char* address : {"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::"}) {
        const auto ip{LookupHost(address, /*fAllowLookup=*/false)};
        BOOST_REQUIRE(ip);
        BOOST_CHECK(ip->IsValid());
    }
}

BOOST_AUTO_TEST_CASE(wait_large_timeout)
{
    TcpPair pair;
    const char byte{'x'};
    BOOST_REQUIRE_EQUAL(pair.client->Send(&byte, 1, MSG_NOSIGNAL), 1);
    Sock::Event occurred{0};
    BOOST_REQUIRE(pair.server->Wait(std::chrono::hours{24 * 365 * 5}, Sock::RecvEvent, &occurred));
    BOOST_CHECK(occurred & Sock::RecvEvent);
}

BOOST_AUTO_TEST_CASE(wait_timeout_does_not_wrap)
{
    TcpPair pair;
    std::atomic<ssize_t> sent{0};
    std::thread sender{[&] {
        std::this_thread::sleep_for(100ms);
        const char byte{'x'};
        sent = pair.client->Send(&byte, 1, MSG_NOSIGNAL);
    }};
    // Narrowing this timeout to a 32-bit int would turn it into one millisecond.
    const std::chrono::milliseconds timeout{(int64_t{1} << 32) + 1};
    Sock::Event occurred{0};
    const bool success{pair.server->Wait(timeout, Sock::RecvEvent, &occurred)};
    sender.join();
    BOOST_REQUIRE_EQUAL(sent.load(), 1);
    BOOST_REQUIRE(success);
    BOOST_CHECK(occurred & Sock::RecvEvent);
}

BOOST_AUTO_TEST_CASE(exception_monitoring_requires_receive)
{
    TcpPair pair;
#ifdef __APPLE__
    // On macOS, urgent data at the start of a TCP stream can fail to trigger
    // exceptional readiness. Exchange a normal byte before sending urgent data.
    const char initial_byte{'x'};
    BOOST_REQUIRE_EQUAL(pair.client->Send(&initial_byte, 1, MSG_NOSIGNAL), 1);
    Sock::Event initial_occurred{0};
    BOOST_REQUIRE(pair.server->Wait(1s, Sock::RecvEvent, &initial_occurred));
    BOOST_REQUIRE(initial_occurred & Sock::RecvEvent);
    char initial_received{};
    BOOST_REQUIRE_EQUAL(pair.server->Recv(&initial_received, 1, 0), 1);
    BOOST_REQUIRE_EQUAL(initial_received, initial_byte);
#endif

    const char urgent{'!'};
    BOOST_REQUIRE_EQUAL(pair.client->Send(&urgent, 1, MSG_OOB | MSG_NOSIGNAL), 1);

    // Wait for the urgent byte to arrive without consuming it. This avoids a
    // timing dependency between the send and the readiness checks below.
    fd_set exceptional;
    FD_ZERO(&exceptional);
    FD_SET(pair.server->Get(), &exceptional);
    timeval timeout{1, 0};
#ifdef WIN32
    const int nfds{0}; // Ignored by Winsock.
#else
    const int nfds{static_cast<int>(pair.server->Get()) + 1};
#endif
    BOOST_REQUIRE_EQUAL(select(nfds, nullptr, nullptr, &exceptional, &timeout), 1);

    Sock::EventsPerSock events;
    events.emplace(pair.server, Sock::Events{0});
    // Winsock requires at least one monitored socket. Keep the idle peer
    // monitored while disabling all events on the socket with urgent data.
    events.emplace(pair.client, Sock::Events{Sock::RecvEvent});
    BOOST_REQUIRE(pair.server->WaitMany(0ms, events));
    BOOST_CHECK_EQUAL(events.at(pair.server).occurred, 0);

    events.at(pair.server).requested = Sock::SendEvent;
    BOOST_REQUIRE(pair.server->WaitMany(0ms, events));
    BOOST_CHECK(events.at(pair.server).occurred & Sock::SendEvent);
    BOOST_CHECK(!(events.at(pair.server).occurred & Sock::ErrorEvent));

#ifndef USE_POLL
    // select() must still report exceptional conditions when receiving is enabled.
    events.at(pair.server).requested = Sock::RecvEvent;
    BOOST_REQUIRE(pair.server->WaitMany(0ms, events));
    BOOST_CHECK(events.at(pair.server).occurred & Sock::ErrorEvent);
#endif

    char received{};
    BOOST_REQUIRE_EQUAL(pair.server->Recv(&received, 1, MSG_OOB), 1);
    BOOST_CHECK_EQUAL(received, urgent);
    const char byte{'x'};
    BOOST_REQUIRE_EQUAL(pair.client->Send(&byte, 1, MSG_NOSIGNAL), 1);
    Sock::Event occurred{0};
    BOOST_REQUIRE(pair.server->Wait(1s, Sock::RecvEvent, &occurred));
    BOOST_CHECK(occurred & Sock::RecvEvent);
    BOOST_REQUIRE_EQUAL(pair.server->Recv(&received, 1, 0), 1);
    BOOST_CHECK_EQUAL(received, byte);
}

BOOST_AUTO_TEST_SUITE_END()
