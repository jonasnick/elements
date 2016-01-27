// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CALLRPC_H
#define BITCOIN_CALLRPC_H

#include "rpcclient.h"
#include "rpcprotocol.h"
#include "uint256.h"
#include "univalue/univalue.h"

#include <string>

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

json_spirit::Object CallRPC(const std::string& strMethod, const json_spirit::Array& params, std::string port="");
std::string CallRPCUniValu(const std::string& strMethod, const json_spirit::Array& params, std::string port="");
bool IsConfirmedBitcoinBlock(const uint256& hash, int nMinConfirmationDepth);
json_spirit::Value getMainchainRawTx(std::string txID, int mode);
std::string getMainchainRawTxUniValue(std::string txID, int mode);
json_spirit::Value getMainchainBlock(std::string blockhash);
json_spirit::Value getMainchainSPVProof(std::vector<json_spirit::Value> txns);

#endif // BITCOIN_CALLRPC_H
