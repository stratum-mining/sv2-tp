// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#include <compat/compat.h>
#include <netaddress.h>
#include <util/sock.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * Wrapper for getaddrinfo(3). Do not use directly: call Lookup/LookupHost/LookupNumeric/LookupSubNet.
 */
std::vector<CNetAddr> WrappedGetAddrInfo(const std::string& name, bool allow_lookup);

using DNSLookupFn = std::function<std::vector<CNetAddr>(const std::string&, bool)>;
extern DNSLookupFn g_dns_lookup;

/**
 * Resolve a host string to its corresponding network addresses.
 *
 * @param name    The string representing a host. Could be a name or a numerical
 *                IP address (IPv6 addresses in their bracketed form are
 *                allowed).
 *
 * @returns The resulting network addresses to which the specified host
 *          string resolved.
 *
 * @see Lookup(const std::string&, uint16_t, bool, unsigned int, DNSLookupFn)
 *      for additional parameter descriptions.
 */
std::vector<CNetAddr> LookupHost(const std::string& name, unsigned int nMaxSolutions, bool fAllowLookup, DNSLookupFn dns_lookup_function = g_dns_lookup);

/**
 * Resolve a host string to its first corresponding network address.
 *
 * @returns The resulting network address to which the specified host
 *          string resolved or std::nullopt if host does not resolve to an address.
 *
 * @see LookupHost(const std::string&, unsigned int, bool, DNSLookupFn)
 *      for additional parameter descriptions.
 */
std::optional<CNetAddr> LookupHost(const std::string& name, bool fAllowLookup, DNSLookupFn dns_lookup_function = g_dns_lookup);

/**
 * Resolve a service string to its corresponding service.
 *
 * @param name    The string representing a service. Could be a name or a
 *                numerical IP address (IPv6 addresses should be in their
 *                disambiguated bracketed form), optionally followed by a uint16_t port
 *                number. (e.g. example.com:8333 or
 *                [2001:db8:85a3:8d3:1319:8a2e:370:7348]:420)
 * @param portDefault The default port for resulting services if not specified
 *                    by the service string.
 * @param fAllowLookup Whether or not hostname lookups are permitted. If yes,
 *                     external queries may be performed.
 * @param nMaxSolutions The maximum number of results we want, specifying 0
 *                      means "as many solutions as we get."
 *
 * @returns The resulting services to which the specified service string
 *          resolved.
 */
std::vector<CService> Lookup(const std::string& name, uint16_t portDefault, bool fAllowLookup, unsigned int nMaxSolutions, DNSLookupFn dns_lookup_function = g_dns_lookup);

/**
 * Resolve a service string to its first corresponding service.
 *
 * @see Lookup(const std::string&, uint16_t, bool, unsigned int, DNSLookupFn)
 *      for additional parameter descriptions.
 */
std::optional<CService> Lookup(const std::string& name, uint16_t portDefault, bool fAllowLookup, DNSLookupFn dns_lookup_function = g_dns_lookup);

/**
 * Resolve a service string with a numeric IP to its first corresponding
 * service.
 *
 * @returns The resulting CService if the resolution was successful, [::]:0 otherwise.
 *
 * @see Lookup(const std::string&, uint16_t, bool, unsigned int, DNSLookupFn)
 *      for additional parameter descriptions.
 */
CService LookupNumeric(const std::string& name, uint16_t portDefault = 0, DNSLookupFn dns_lookup_function = g_dns_lookup);

/**
 * Parse and resolve a specified subnet string into the appropriate internal
 * representation.
 *
 * @param[in]  subnet_str  A string representation of a subnet of the form
 *                         `network address [ "/", ( CIDR-style suffix | netmask ) ]`
 *                         e.g. "2001:db8::/32", "192.0.2.0/255.255.255.0" or "8.8.8.8".
 * @returns a CSubNet object (that may or may not be valid).
 */
CSubNet LookupSubNet(const std::string& subnet_str);

/**
 * Create a real socket from the operating system.
 * @param[in] domain Communications domain, first argument to the socket(2) syscall.
 * @param[in] type Type of the socket, second argument to the socket(2) syscall.
 * @param[in] protocol The particular protocol to be used with the socket, third argument to the socket(2) syscall.
 * @return pointer to the created Sock object or unique_ptr that owns nothing in case of failure
 */
std::unique_ptr<Sock> CreateSockOS(int domain, int type, int protocol);

/**
 * Socket factory. Defaults to `CreateSockOS()`, but can be overridden by unit tests.
 */
extern std::function<std::unique_ptr<Sock>(int, int, int)> CreateSock;

/** Get the bind address for a socket as CService. */
CService GetBindAddress(const Sock& sock);

#endif // BITCOIN_NETBASE_H
