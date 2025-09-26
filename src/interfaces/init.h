// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_INIT_H
#define BITCOIN_INTERFACES_INIT_H

#include <interfaces/echo.h>
#include <interfaces/mining.h>

#include <memory>

namespace interfaces {
class Ipc;

//! Initial interface created when a process is first started.
//!
//! The SV2 fork only exposes the Mining interface needed by the template
//! provider, so the default implementation simply returns null.
class Init
{
public:
    virtual ~Init() = default;
    virtual std::unique_ptr<Echo> makeEcho() { return nullptr; }
    virtual std::unique_ptr<Mining> makeMining() { return nullptr; }
    virtual Ipc* ipc() { return nullptr; }
    virtual bool canListenIpc() { return false; }
};

//! Return implementation of Init interface for a basic IPC client that doesn't
//! provide any IPC services itself.
//!
//! When an IPC client connects to a socket or spawns a process, it gets a pointer
//! to an Init object allowing it to create objects and threads on the remote
//! side of the IPC connection. But the client also needs to provide a local Init
//! object to allow the remote side of the connection to create objects and
//! threads on this side. This function just returns a basic Init object
//! allowing remote connections to only create local threads, not other objects
//! (because its Init::make* methods return null.)
//!
//! @param exe_name Current executable name, which is just passed to the IPC
//!     system and used for logging.
//!
//! @param process_argv0 Optional string containing argv[0] value passed to
//!     main(). This is passed to the IPC system and used to locate binaries by
//!     relative path if subprocesses are spawned.
std::unique_ptr<Init> MakeBasicInit(const char* exe_name, const char* process_argv0="");
} // namespace interfaces

#endif // BITCOIN_INTERFACES_INIT_H
