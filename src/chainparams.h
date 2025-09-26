// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <string>
#include <util/chaintype.h>

class CChainParams
{
public:
    explicit CChainParams(ChainType chain_type);

    std::string GetChainTypeString() const;
    ChainType GetChainType() const { return m_chain_type; }

protected:
    ChainType m_chain_type;
};

void SelectParams(ChainType chain);

#endif // BITCOIN_CHAINPARAMS_H
