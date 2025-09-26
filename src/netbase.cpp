// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <netbase.h>

#include <compat/compat.h>
#include <logging.h>
#include <util/sock.h>
#include <util/strencodings.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

#ifdef HAVE_SOCKADDR_UN
#include <sys/un.h>
#endif

using util::ContainsNoNUL;

std::vector<CNetAddr> WrappedGetAddrInfo(const std::string& name, bool allow_lookup)
{
    addrinfo ai_hint{};
    // We want a TCP port, which is a streaming socket type
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;
    // We don't care which address family (IPv4 or IPv6) is returned
    ai_hint.ai_family = AF_UNSPEC;

    // If we allow lookups of hostnames, use the AI_ADDRCONFIG flag to only
    // return addresses whose family we have an address configured for.
    //
    // If we don't allow lookups, then use the AI_NUMERICHOST flag for
    // getaddrinfo to only decode numerical network addresses and suppress
    // hostname lookups.
    ai_hint.ai_flags = allow_lookup ? AI_ADDRCONFIG : AI_NUMERICHOST;

    addrinfo* ai_res{nullptr};
    const int n_err{getaddrinfo(name.c_str(), nullptr, &ai_hint, &ai_res)};
    if (n_err != 0) {
        if ((ai_hint.ai_flags & AI_ADDRCONFIG) == AI_ADDRCONFIG) {
            // AI_ADDRCONFIG on some systems may exclude loopback-only addresses
            // If first lookup failed we perform a second lookup without AI_ADDRCONFIG
            ai_hint.ai_flags = (ai_hint.ai_flags & ~AI_ADDRCONFIG);
            const int n_err_retry{getaddrinfo(name.c_str(), nullptr, &ai_hint, &ai_res)};
            if (n_err_retry != 0) {
                return {};
            }
        } else {
            return {};
        }
    }

    // Traverse the linked list starting with ai_trav.
    addrinfo* ai_trav{ai_res};
    std::vector<CNetAddr> resolved_addresses;
    while (ai_trav != nullptr) {
        if (ai_trav->ai_family == AF_INET) {
            assert(ai_trav->ai_addrlen >= sizeof(sockaddr_in));
            resolved_addresses.emplace_back(reinterpret_cast<sockaddr_in*>(ai_trav->ai_addr)->sin_addr);
        }
        if (ai_trav->ai_family == AF_INET6) {
            assert(ai_trav->ai_addrlen >= sizeof(sockaddr_in6));
            const sockaddr_in6* s6{reinterpret_cast<sockaddr_in6*>(ai_trav->ai_addr)};
            resolved_addresses.emplace_back(s6->sin6_addr, s6->sin6_scope_id);
        }
        ai_trav = ai_trav->ai_next;
    }
    freeaddrinfo(ai_res);

    return resolved_addresses;
}

DNSLookupFn g_dns_lookup{WrappedGetAddrInfo};

static std::vector<CNetAddr> LookupIntern(const std::string& name, unsigned int nMaxSolutions, bool fAllowLookup, DNSLookupFn dns_lookup_function)
{
    if (!ContainsNoNUL(name)) return {};

    std::vector<CNetAddr> addresses;

    for (const CNetAddr& resolved : dns_lookup_function(name, fAllowLookup)) {
        if (nMaxSolutions > 0 && addresses.size() >= nMaxSolutions) {
            break;
        }
        /* Never allow resolving to an internal address. Consider any such result invalid */
        if (!resolved.IsInternal()) {
            addresses.push_back(resolved);
        }
    }

    return addresses;
}

std::vector<CNetAddr> LookupHost(const std::string& name, unsigned int nMaxSolutions, bool fAllowLookup, DNSLookupFn dns_lookup_function)
{
    if (!ContainsNoNUL(name)) return {};
    std::string strHost = name;
    if (strHost.empty()) return {};
    if (strHost.front() == '[' && strHost.back() == ']') {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return LookupIntern(strHost, nMaxSolutions, fAllowLookup, dns_lookup_function);
}

std::optional<CNetAddr> LookupHost(const std::string& name, bool fAllowLookup, DNSLookupFn dns_lookup_function)
{
    const std::vector<CNetAddr> addresses{LookupHost(name, 1, fAllowLookup, dns_lookup_function)};
    return addresses.empty() ? std::nullopt : std::make_optional(addresses.front());
}

std::vector<CService> Lookup(const std::string& name, uint16_t portDefault, bool fAllowLookup, unsigned int nMaxSolutions, DNSLookupFn dns_lookup_function)
{
    if (name.empty() || !ContainsNoNUL(name)) {
        return {};
    }
    uint16_t port{portDefault};
    std::string hostname;
    SplitHostPort(name, port, hostname);

    const std::vector<CNetAddr> addresses{LookupIntern(hostname, nMaxSolutions, fAllowLookup, dns_lookup_function)};
    if (addresses.empty()) return {};
    std::vector<CService> services;
    services.reserve(addresses.size());
    for (const auto& addr : addresses)
        services.emplace_back(addr, port);
    return services;
}

std::optional<CService> Lookup(const std::string& name, uint16_t portDefault, bool fAllowLookup, DNSLookupFn dns_lookup_function)
{
    const std::vector<CService> services{Lookup(name, portDefault, fAllowLookup, 1, dns_lookup_function)};

    return services.empty() ? std::nullopt : std::make_optional(services.front());
}

CService LookupNumeric(const std::string& name, uint16_t portDefault, DNSLookupFn dns_lookup_function)
{
    if (!ContainsNoNUL(name)) {
        return {};
    }
    // "1.2:345" will fail to resolve the ip, but will still set the port.
    // If the ip fails to resolve, re-init the result.
    return Lookup(name, portDefault, /*fAllowLookup=*/false, dns_lookup_function).value_or(CService{});
}

std::unique_ptr<Sock> CreateSockOS(int domain, int type, int protocol)
{
    // Not IPv4, IPv6 or UNIX
    if (domain == AF_UNSPEC) return nullptr;

    // Create a socket in the specified address family.
    SOCKET hSocket = socket(domain, type, protocol);
    if (hSocket == INVALID_SOCKET) {
        return nullptr;
    }

    auto sock = std::make_unique<Sock>(hSocket);

    if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX) {
        return sock;
    }

    // Ensure that waiting for I/O on this socket won't result in undefined
    // behavior.
    if (!sock->IsSelectable()) {
        LogPrintf("Cannot create connection: non-selectable socket created (fd >= FD_SETSIZE ?)\n");
        return nullptr;
    }

#ifdef SO_NOSIGPIPE
    int set = 1;
    // Set the no-sigpipe option on the socket for BSD systems, other UNIXes
    // should use the MSG_NOSIGNAL flag for every send.
    if (sock->SetSockOpt(SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int)) == SOCKET_ERROR) {
        LogPrintf("Error setting SO_NOSIGPIPE on socket: %s, continuing anyway\n",
                  NetworkErrorString(WSAGetLastError()));
    }
#endif

    // Set the non-blocking option on the socket.
    if (!sock->SetNonBlocking()) {
        LogPrintf("Error setting socket to non-blocking: %s\n", NetworkErrorString(WSAGetLastError()));
        return nullptr;
    }

#ifdef HAVE_SOCKADDR_UN
    if (domain == AF_UNIX) return sock;
#endif

    if (protocol == IPPROTO_TCP) {
        // Set the no-delay option (disable Nagle's algorithm) on the TCP socket.
        const int on{1};
        if (sock->SetSockOpt(IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == SOCKET_ERROR) {
            LogDebug(BCLog::NET, "Unable to set TCP_NODELAY on a newly created socket, continuing anyway\n");
        }
    }

    return sock;
}

std::function<std::unique_ptr<Sock>(int, int, int)> CreateSock = CreateSockOS;

CSubNet LookupSubNet(const std::string& subnet_str)
{
    CSubNet subnet;
    assert(!subnet.IsValid());
    if (!ContainsNoNUL(subnet_str)) {
        return subnet;
    }

    const size_t slash_pos{subnet_str.find_last_of('/')};
    const std::string str_addr{subnet_str.substr(0, slash_pos)};
    std::optional<CNetAddr> addr{LookupHost(str_addr, /*fAllowLookup=*/false)};

    if (addr.has_value()) {
        if (slash_pos != subnet_str.npos) {
            const std::string netmask_str{subnet_str.substr(slash_pos + 1)};
            if (const auto netmask{ToIntegral<uint8_t>(netmask_str)}) {
                // Valid number; assume CIDR variable-length subnet masking.
                subnet = CSubNet{addr.value(), *netmask};
            } else {
                // Invalid number; try full netmask syntax. Never allow lookup for netmask.
                const std::optional<CNetAddr> full_netmask{LookupHost(netmask_str, /*fAllowLookup=*/false)};
                if (full_netmask.has_value()) {
                    subnet = CSubNet{addr.value(), full_netmask.value()};
                }
            }
        } else {
            // Single IP subnet (<ipv4>/32 or <ipv6>/128).
            subnet = CSubNet{addr.value()};
        }
    }

    return subnet;
}

CService GetBindAddress(const Sock& sock)
{
    CService addr_bind;
    struct sockaddr_storage sockaddr_bind;
    socklen_t sockaddr_bind_len = sizeof(sockaddr_bind);
    if (!sock.GetSockName((struct sockaddr*)&sockaddr_bind, &sockaddr_bind_len)) {
        addr_bind.SetSockAddr((const struct sockaddr*)&sockaddr_bind, sockaddr_bind_len);
    } else {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "getsockname failed\n");
    }
    return addr_bind;
}
