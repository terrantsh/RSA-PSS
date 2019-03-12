//
// Created by Administrator on 2019/3/11.
//

#ifndef WOLFSSL_RSAPSS_HASH_H
#define WOLFSSL_RSAPSS_HASH_H

#include "types.h"
#include "sha256.h"

enum {
    WC_SHA512_BLOCK_SIZE   = 128,
    WC_SHA512_DIGEST_SIZE  =  64,
    WC_SHA512_PAD_SIZE     = 112
};

#define WC_MAX_DIGEST_SIZE WC_SHA512_DIGEST_SIZE

word32 wc_HashGetDigestSize(enum wc_HashType hash_type);
int wc_Hash(enum wc_HashType hash_type, const byte* data, word32 data_len, byte* hash, word32 hash_len);

#endif //WOLFSSL_RSAPSS_HASH_H
