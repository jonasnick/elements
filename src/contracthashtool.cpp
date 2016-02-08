
#include "contracthashtool.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "base58.h"
#include <string.h>
#include "utilstrencodings.h"
#include "crypto/hmac_sha256.h"
#include "random.h"
#include "util.h"
#include "key.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorr.h>

secp256k1_context *secp256k1_ctx_cht = NULL;


int get_pubkeys_from_redeemscript(unsigned char *redeem_script, unsigned int redeem_script_len, unsigned char* pubkeys[]) {
    unsigned char *readpos = redeem_script, * const endpos = redeem_script + redeem_script_len;
    unsigned char *maybe_keys[redeem_script_len/33];
    unsigned int maybe_keys_count = 0, pubkeys_count = 0;;
    bool require_next_checkmultisig = false;

    while (readpos < endpos) {
        int pushlen = -1;
        unsigned char* push_start = NULL;

        if (*readpos > 0 && *readpos < 76) {
            pushlen = *readpos;
            push_start = readpos + 1;
        } else if (*readpos == 76) {
            if (readpos + 1 >= endpos) {
                LogPrint("ContractHashTool", "Invalid push in script\n");
                return -1;
            }
            pushlen = *(readpos + 1);
            push_start = readpos + 2;
        } else if (*readpos == 77) {
            if (readpos + 2 >= endpos) {
                LogPrint("ContractHashTool", "Invalid push in script\n");
                return -1;
            }
            pushlen = *(readpos + 1) | (*(readpos + 2) << 8);
            push_start = readpos + 3;
        } else if (*readpos == 78) {
            if (readpos + 4 >= endpos) {
                LogPrint("ContractHashTool", "Invalid push in script\n");
                return -1;
            }
            pushlen = *(readpos + 1) | (*(readpos + 2) << 8) | (*(readpos + 3) << 16) | (*(readpos + 4) << 24);
            push_start = readpos + 5;
        }

        if (pushlen > -1) {
            if (push_start + pushlen >= endpos) {
                LogPrint("ContractHashTool", "Invalid push in script\n");
                return -1;
            }

            if (pushlen == 65 && *push_start == 4) {
                LogPrint("ContractHashTool", "ERROR: Possible uncompressed pubkey found in redeem script, not converting it\n");
                return -1;
            }
            else if (pushlen == 33 && (*push_start == 2 || *push_start == 3))
                maybe_keys[maybe_keys_count++] = push_start;
            else if (maybe_keys_count > 0) {
                LogPrint("ContractHashTool", "ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
                return -1;
            }
        } else {
            if (require_next_checkmultisig) {
                if (*readpos == 174 || *readpos == 175) {
                    require_next_checkmultisig = false;
                    for (unsigned int i = 0; i < maybe_keys_count; i++)
                        pubkeys[pubkeys_count++] = maybe_keys[i];
                    maybe_keys_count = 0;
                } else {
                    LogPrint("ContractHashTool", "ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
                    return -1;
                }
            } else if (maybe_keys_count > 0) {
                if (maybe_keys_count == 1 && (*readpos == 172 || *readpos == 173)) {
                    pubkeys[pubkeys_count++] = maybe_keys[0];
                    maybe_keys_count = 0;
                } else if (((unsigned int)*readpos) - 80 == maybe_keys_count)
                    require_next_checkmultisig = true;
                else {
                    LogPrint("ContractHashTool", "ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
                    return -1;
                }
            } else if (*readpos >= 172 && *readpos <= 175) {
                LogPrint("ContractHashTool", "ERROR: Found OP_CHECK[MULTI]SIG[VERIFY] without pubkey(s) immediately preceeding it\n");
                return -1;
            }
        }

        if (pushlen != -1)
            readpos = push_start + pushlen;
        else
            readpos++;
    }

    return pubkeys_count;
}

bool hex2bytes(const char* c, unsigned char* res, unsigned int len) {
    std::vector<unsigned char> hex = ParseHex(c);
    if (hex.size() != len)
        return false;
    memcpy(res, &hex[0], len);
    return true;
}

json_spirit::Value contract_hashtool(const char mode, const char* redeem_script_hex, const char* p2sh_address, const char* priv_key_str, const char* nonce_hex, const char* fullcontract_hex, const char* ascii_contract) {
    int i;
    // ARGCHECK
    if (!p2sh_address&& !ascii_contract && !fullcontract_hex) {
        LogPrint("ContractHashTool", "No contract provided\n");
        return json_spirit::Value::null;
    }
    if (mode == 0x1 && !redeem_script_hex) {
        LogPrint("ContractHashTool", "No redeem script specified\n");
        return json_spirit::Value::null;
    }
    if (mode == 0x2 && !nonce_hex && !fullcontract_hex) {
        LogPrint("ContractHashTool", "No nonce specified\n");
        return json_spirit::Value::null;
    }
    if (mode == 0x2 && !priv_key_str) {
        LogPrint("ContractHashTool", "No private key specified\n");
        return json_spirit::Value::null;
    }

    if (secp256k1_ctx_cht == NULL) {
        secp256k1_ctx_cht = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);
    }

    // GLOBALCONV
    unsigned char p2sh_bytes[20];
    const char* address_type = "TEXT";
    if (p2sh_address) {
        CBitcoinAddress addr(p2sh_address);
        if (!addr.IsValid()) {
            return json_spirit::Value::null;
        }
        CTxDestination dest = addr.Get();
        //Non-no-dest address
        if (dest.which() == 1) {
            memcpy(p2sh_bytes, boost::get<CKeyID>(dest).begin(), 20);
        }
        else if (dest.which() ==2) {
            memcpy(p2sh_bytes, boost::get<CScriptID>(dest).begin(), 20);
        }
        else {
            return json_spirit::Value::null;
        }
        address_type = (addr.IsScript() ? "P2SH" : "P2PH");
    }

    unsigned char nonce[16];
    if (nonce_hex && !hex2bytes(nonce_hex, nonce, 16))
        return json_spirit::Value::null;
    
    if (fullcontract_hex) {
        unsigned char fullcontract[40];
        if (!hex2bytes(fullcontract_hex, fullcontract, 40)) {
            return json_spirit::Value::null;
        }
        if (memcmp(fullcontract, "P2SH", 4) == 0)
            address_type = "P2SH";
        else if (memcmp(fullcontract, "P2PH", 4) == 0)
            address_type = "P2SH";
        else {
            return json_spirit::Value::null;
        }

        memcpy(nonce, fullcontract + 4, sizeof(nonce));
        nonce_hex = "42"; // Later logic needs to check if nonce is fixed

        memcpy(p2sh_bytes, fullcontract + 4 + sizeof(nonce), sizeof(p2sh_bytes));
    }

    unsigned int targetLen = ascii_contract ? strlen(ascii_contract) : 20;

    json_spirit::Object ret;

    if (mode == 0x1) {
        unsigned int redeem_script_len = strlen(redeem_script_hex)/2;
        unsigned char redeem_script[redeem_script_len];
        if (!hex2bytes(redeem_script_hex, redeem_script, redeem_script_len)) {
            return json_spirit::Value::null;
        }
        unsigned char* keys[redeem_script_len / 33];
        int key_count = get_pubkeys_from_redeemscript(redeem_script, redeem_script_len, keys);
        if (key_count < 1) {
            return json_spirit::Value::null;
        }
    
        unsigned char data[4 + 16 + targetLen];
        memset(data,                         0,              4);
        memcpy(data,                         address_type,   strlen(address_type));
        if (ascii_contract)
            memcpy(data + 4 + sizeof(nonce), ascii_contract, strlen(ascii_contract));
        else
            memcpy(data + 4 + sizeof(nonce), p2sh_bytes,     sizeof(p2sh_bytes));

        unsigned char keys_work[key_count][33];
        while (true) {
            for (i = 0; i < key_count; i++)
                memcpy(keys_work[i], keys[i], 33);

            if (!nonce_hex) {
                GetRandBytes(nonce, 16);
            }
            memcpy(data + 4,                     nonce,          sizeof(nonce));

            for (i = 0; i < key_count; i++) {
                unsigned char res[32];
                CHMAC_SHA256(keys_work[i], 33).Write(data, 4 + 16 + targetLen).Finalize(res);
                secp256k1_pubkey pubkey;
                if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_cht, &pubkey, keys_work[i], 33)) {
                    return json_spirit::Value::null;
                }
                // If tweak puts key over order, break or exit depending on fixed nonce
                if (secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_cht, &pubkey, res) == 0) {
                    if (nonce_hex) {
                        return json_spirit::Value::null;
                    }
                    break;
                }
                size_t len = 33;
                secp256k1_ec_pubkey_serialize(secp256k1_ctx_cht, keys_work[i], &len, &pubkey, SECP256K1_EC_COMPRESSED);
                assert(len == 33);
            }
            // Break if all keys have been successfully tweaked
            if (i == key_count)
                break;
        }
        for (i = 0; i < key_count; i++)
            memcpy(keys[i], keys_work[i], 33);

        CScript redeemer(redeem_script, redeem_script+redeem_script_len);
        CScriptID innerID(redeemer);
        CBitcoinAddress tweakedAddr(innerID);

        char out[1000];
        for (int i = 0; i < 16; i++)
            sprintf(out+(i*2), "%02x", nonce[i]);
        ret.push_back(Pair("nonce", std::string(out, 32)));
        for (unsigned int i =0 ; i < 4 + 16 + targetLen; i++)
            sprintf(out+(i*2), "%02x", data[i]);
        ret.push_back(Pair("fullcontract", std::string(out, (4 + 16 + targetLen)*2)));
        for (unsigned int i = 0; i < redeem_script_len; i++)
            sprintf(out+(i*2), "%02x", redeem_script[i]);
        ret.push_back(Pair("redeem", std::string(out, redeem_script_len*2)));
        ret.push_back(Pair("p2sh", tweakedAddr.ToString()));
    } else if (mode == 0x2) {
        unsigned char priv[33], pub[33];
        secp256k1_pubkey pubkey;

        //Check validity of private key string then copy to bytes
        CBitcoinSecret secret;
        secret.SetString(priv_key_str);
        if (!secret.IsValid()) {
            return json_spirit::Value::null;
        }
        std::vector<unsigned char> vPriv;
        DecodeBase58(priv_key_str, vPriv);
        memcpy(priv, &vPriv[0], 33);

        // Create data to commit to
        unsigned char data[4 + 16 + targetLen];
        memset(data,                         0,              4);
        memcpy(data,                         address_type,   strlen(address_type));
        memcpy(data + 4,                     nonce,          sizeof(nonce));
        if (ascii_contract)
            memcpy(data + 4 + sizeof(nonce), ascii_contract, strlen(ascii_contract));
        else
            memcpy(data + 4 + sizeof(nonce), p2sh_bytes,     sizeof(p2sh_bytes));

        // Gen public key from private
        size_t len = 33;
        if (secp256k1_ec_pubkey_create(secp256k1_ctx_cht, &pubkey, priv) != 1) {
            return json_spirit::Value::null;
        }
        secp256k1_ec_pubkey_serialize(secp256k1_ctx_cht, pub, &len, &pubkey, SECP256K1_EC_COMPRESSED);
        assert(len == 33);

        // Gen new private key by tweaking based on commitment to pubkey and data
        unsigned char tweak[32];
        CHMAC_SHA256(pub, 33).Write(data, 4 + 16 + targetLen).Finalize(tweak);

        if (secp256k1_ec_privkey_tweak_add(secp256k1_ctx_cht, priv, tweak) != 1) {
            return json_spirit::Value::null;
        }

        priv[32] = 1;
        CKey privKey;
        privKey.Set(priv, priv+33, true);
        ret.push_back(Pair("priv", CBitcoinSecret(privKey).ToString()));
    } else {
        return json_spirit::Value::null;
    }
    
    return ret;
}

