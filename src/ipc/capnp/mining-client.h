// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_CAPNP_MINING_CLIENT_H
#define BITCOIN_IPC_CAPNP_MINING_CLIENT_H

#include <interfaces/mining.h>
#include <ipc/capnp/mining.capnp.h>
#include <mp/proxy.h>

namespace mp {
//! Keep the typed interface while receiving the block as bytes over IPC.
template <>
class ProxyClientCustom<ipc::capnp::messages::BlockTemplate, interfaces::BlockTemplate>
    : public ProxyClientBase<ipc::capnp::messages::BlockTemplate, interfaces::BlockTemplate>
{
public:
    using ProxyClientBase::ProxyClientBase;
    CBlock getBlock() override;
};
} // namespace mp

#endif // BITCOIN_IPC_CAPNP_MINING_CLIENT_H
