// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <util/chaintype.h>

CChainParams::CChainParams(ChainType chain_type) : m_chain_type{chain_type} {}

std::string CChainParams::GetChainTypeString() const
{
    return ChainTypeToString(m_chain_type);
}

void SelectParams(ChainType chain)
{
    SelectBaseParams(chain);
}
