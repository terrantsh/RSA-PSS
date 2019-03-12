//
// Created by Administrator on 2019/3/11.
//

#include "hash.h"

int wc_Sha256Hash(const byte* data, word32 len, byte* hash)
{
    int ret = 0;
    wc_Sha256 sha256[1];
    if ((ret = wc_InitSha256(sha256)) != 0) {
    }
    else {
        if ((ret = wc_Sha256Update(sha256, data, len)) != 0) {
        }
        else if ((ret = wc_Sha256Final(sha256, hash)) != 0) {
        }
    }
    return ret;
}

/* Get Hash digest size */
word32 wc_HashGetDigestSize(enum wc_HashType hash_type)
{
    word32 dig_size = HASH_TYPE_E; /* Default to hash type error */
    switch(hash_type)
    {
        case WC_HASH_TYPE_SHA256:
#ifndef NO_SHA256
            dig_size = WC_SHA256_DIGEST_SIZE;
#endif
            break;

            /* Not Supported */
        case WC_HASH_TYPE_BLAKE2B:
        case WC_HASH_TYPE_NONE:
        default:
            dig_size = BAD_FUNC_ARG;
            break;
    }
    return dig_size;
}

/* Generic Hashing Wrapper */
int wc_Hash(enum wc_HashType hash_type, const byte* data,
            word32 data_len, byte* hash, word32 hash_len)
{
    int ret = HASH_TYPE_E; /* Default to hash type error */
    word32 dig_size;

    /* Validate hash buffer size */
    dig_size = wc_HashGetDigestSize(hash_type);
    if (hash_len < dig_size) {
        return BUFFER_E;
    }

    /* Suppress possible unused arg if all hashing is disabled */
    (void)data;
    (void)data_len;
    (void)hash;
    (void)hash_len;

    switch(hash_type)
    {

        case WC_HASH_TYPE_SHA256:
#ifndef NO_SHA256
            ret = wc_Sha256Hash(data, data_len, hash);
#endif
            break;
            /* Not Supported */
        case WC_HASH_TYPE_MD2:
        case WC_HASH_TYPE_MD4:
        case WC_HASH_TYPE_SHA3_224:
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512:
        case WC_HASH_TYPE_BLAKE2B:
        case WC_HASH_TYPE_NONE:
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    return ret;
}