
#ifndef CONTRACTHASH_H
#define CONTRACTHASH_H

#include <stdio.h>
#include <stdlib.h>
#include "json/json_spirit_writer_template.h"
using namespace json_spirit;



int get_pubkeys_from_redeemscript(unsigned char *redeem_script, unsigned int redeem_script_len, unsigned char* pubkeys[]);

bool hex2bytes(const char* c, unsigned char* res, unsigned int len);

json_spirit::Value contract_hashtool(const char mode, const char* redeem_script_hex, const char* p2sh_address, const char* priv_key_str, const char* nonce_hex, const char* fullcontract_hex, const char* ascii_contract);

#endif
