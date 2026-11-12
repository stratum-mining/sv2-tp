// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ipc/capnp/mining-client.h>
#include <ipc/capnp/mining-types.h>
#include <ipc/capnp/mining.capnp.proxy-types.h>

#include <mp/proxy-types.h>
#include <streams.h>

namespace mp {
CBlock ProxyClientCustom<ipc::capnp::messages::BlockTemplate, interfaces::BlockTemplate>::getBlock()
{
    const auto serialized = getSerializedBlock();
    CBlock block;
    SpanReader reader{MakeByteSpan(serialized.bytes)};
    reader >> TX_WITH_WITNESS(block);
    return block;
}
} // namespace mp
