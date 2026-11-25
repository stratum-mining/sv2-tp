// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_SERIALIZED_H
#define BITCOIN_IPC_SERIALIZED_H

#include <vector>

namespace ipc {
//! Owned serialization of T. IPC clients can retain large payloads without
//! constructing T on the IPC event-loop thread.
template <typename T>
struct Serialized {
    std::vector<unsigned char> bytes;
};
} // namespace ipc

#endif // BITCOIN_IPC_SERIALIZED_H
