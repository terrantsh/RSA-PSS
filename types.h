//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_TYPES_H
#define WOLFSSL_RSAPSS_TYPES_H

#include <string.h>
#include <stdlib.h>
#include "memory.h"

#define WC_RSA_BLINDING
#define LITTLE_ENDIAN_ORDER
#define NO_DEV_RANDOM

typedef struct              RsaKey RsaKey;
typedef struct              WC_RNG WC_RNG;
typedef unsigned int        mp_digit;  /* long could be 64 now, changed TAO */
typedef unsigned long       ProviderHandle;
typedef unsigned char       byte;
typedef unsigned int        word32;
typedef unsigned short      word16;

#define INVALID_DEVID    -2
#define WC_INLINE __inline
#define STATIC static
#define FALL_THROUGH
#define BN_FAST_MP_INVMOD_C
#define BN_MP_INVMOD_C
#define BN_MP_REDUCE_IS_2K_L_C
#define BN_MP_REDUCE_2K_L_C
#define BN_S_MP_EXPTMOD_C
#define BN_MP_DR_IS_MODULUS_C
#define BN_MP_REDUCE_IS_2K_C
#define BN_FAST_S_MP_SQR_C
#define BN_S_MP_SQR_C
#define BN_FAST_S_MP_MUL_DIGS_C
#define WOLFSSL_SMALL_STACK
#define BN_MP_EXPTMOD_FAST_C
#define BN_MP_MONTGOMERY_SETUP_C
#define BN_FAST_MP_MONTGOMERY_REDUCE_C
#define BN_MP_MONTGOMERY_REDUCE_C
#define BN_MP_DR_SETUP_C
#define BN_MP_DR_REDUCE_C
#define BN_MP_REDUCE_2K_SETUP_C
#define BN_MP_REDUCE_2K_C
#define BN_MP_MONTGOMERY_CALC_NORMALIZATION_C
#define WC_RSA_PSS

#define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
#define XMEMSET(b,c,l)    memset((b),(c),(l))
#define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
#define XMALLOC(s, h, t)  ((void)h, (void)t, wolfSSL_Malloc((s)))
#define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

#define DECLARE_VAR_INIT(VAR_NAME, VAR_TYPE, VAR_SIZE, INIT_VALUE, HEAP) \
            VAR_TYPE* VAR_NAME = (VAR_TYPE*)INIT_VALUE
#define DECLARE_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP) \
            VAR_TYPE VAR_NAME[VAR_SIZE]
#define FREE_VAR(VAR_NAME, HEAP) /* nothing to free, its stack */

enum wc_HashType {
    WC_HASH_TYPE_NONE = 0,
    WC_HASH_TYPE_MD2 = 1,
    WC_HASH_TYPE_MD4 = 2,
    WC_HASH_TYPE_MD5 = 3,
    WC_HASH_TYPE_SHA = 4, /* SHA-1 (not old SHA-0) */
    WC_HASH_TYPE_SHA224 = 5,
    WC_HASH_TYPE_SHA256 = 6,
    WC_HASH_TYPE_SHA384 = 7,
    WC_HASH_TYPE_SHA512 = 8,
    WC_HASH_TYPE_MD5_SHA = 9,
    WC_HASH_TYPE_SHA3_224 = 10,
    WC_HASH_TYPE_SHA3_256 = 11,
    WC_HASH_TYPE_SHA3_384 = 12,
    WC_HASH_TYPE_SHA3_512 = 13,
    WC_HASH_TYPE_BLAKE2B = 14,

    WC_HASH_TYPE_MAX = WC_HASH_TYPE_BLAKE2B
};

/* the mp_int structure */
typedef struct mp_int {
    int used, alloc, sign;
    mp_digit *dp;
} mp_int;

/* RSA */
struct RsaKey {
    mp_int n, e;
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    mp_int d, p, q;
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    mp_int dP, dQ, u;
#endif
#endif
    void* heap;                               /* for user memory overrides */
    byte* data;                               /* temp buffer for async RSA */
    int   type;                               /* public or private */
    int   state;
    word32 dataLen;
    WC_RNG* rng;                              /* for PrivateDecrypt blinding */
    byte   dataIsAlloc;
};

/* memory allocation types for user hints */
enum {
    DYNAMIC_TYPE_CA           = 1,
    DYNAMIC_TYPE_CERT         = 2,
    DYNAMIC_TYPE_KEY          = 3,
    DYNAMIC_TYPE_FILE         = 4,
    DYNAMIC_TYPE_SUBJECT_CN   = 5,
    DYNAMIC_TYPE_PUBLIC_KEY   = 6,
    DYNAMIC_TYPE_SIGNER       = 7,
    DYNAMIC_TYPE_NONE         = 8,
    DYNAMIC_TYPE_BIGINT       = 9,
    DYNAMIC_TYPE_RSA          = 10,
    DYNAMIC_TYPE_METHOD       = 11,
    DYNAMIC_TYPE_OUT_BUFFER   = 12,
    DYNAMIC_TYPE_IN_BUFFER    = 13,
    DYNAMIC_TYPE_INFO         = 14,
    DYNAMIC_TYPE_DH           = 15,
    DYNAMIC_TYPE_DOMAIN       = 16,
    DYNAMIC_TYPE_SSL          = 17,
    DYNAMIC_TYPE_CTX          = 18,
    DYNAMIC_TYPE_WRITEV       = 19,
    DYNAMIC_TYPE_OPENSSL      = 20,
    DYNAMIC_TYPE_DSA          = 21,
    DYNAMIC_TYPE_CRL          = 22,
    DYNAMIC_TYPE_REVOKED      = 23,
    DYNAMIC_TYPE_CRL_ENTRY    = 24,
    DYNAMIC_TYPE_CERT_MANAGER = 25,
    DYNAMIC_TYPE_CRL_MONITOR  = 26,
    DYNAMIC_TYPE_OCSP_STATUS  = 27,
    DYNAMIC_TYPE_OCSP_ENTRY   = 28,
    DYNAMIC_TYPE_ALTNAME      = 29,
    DYNAMIC_TYPE_SUITES       = 30,
    DYNAMIC_TYPE_CIPHER       = 31,
    DYNAMIC_TYPE_RNG          = 32,
    DYNAMIC_TYPE_ARRAYS       = 33,
    DYNAMIC_TYPE_DTLS_POOL    = 34,
    DYNAMIC_TYPE_SOCKADDR     = 35,
    DYNAMIC_TYPE_LIBZ         = 36,
    DYNAMIC_TYPE_ECC          = 37,
    DYNAMIC_TYPE_TMP_BUFFER   = 38,
    DYNAMIC_TYPE_DTLS_MSG     = 39,
    DYNAMIC_TYPE_X509         = 40,
    DYNAMIC_TYPE_TLSX         = 41,
    DYNAMIC_TYPE_OCSP         = 42,
    DYNAMIC_TYPE_SIGNATURE    = 43,
    DYNAMIC_TYPE_HASHES       = 44,
    DYNAMIC_TYPE_SRP          = 45,
    DYNAMIC_TYPE_COOKIE_PWD   = 46,
    DYNAMIC_TYPE_USER_CRYPTO  = 47,
    DYNAMIC_TYPE_OCSP_REQUEST = 48,
    DYNAMIC_TYPE_X509_EXT     = 49,
    DYNAMIC_TYPE_X509_STORE   = 50,
    DYNAMIC_TYPE_X509_CTX     = 51,
    DYNAMIC_TYPE_URL          = 52,
    DYNAMIC_TYPE_DTLS_FRAG    = 53,
    DYNAMIC_TYPE_DTLS_BUFFER  = 54,
    DYNAMIC_TYPE_SESSION_TICK = 55,
    DYNAMIC_TYPE_PKCS         = 56,
    DYNAMIC_TYPE_MUTEX        = 57,
    DYNAMIC_TYPE_PKCS7        = 58,
    DYNAMIC_TYPE_AES_BUFFER   = 59,
    DYNAMIC_TYPE_WOLF_BIGINT  = 60,
    DYNAMIC_TYPE_ASN1         = 61,
    DYNAMIC_TYPE_LOG          = 62,
    DYNAMIC_TYPE_WRITEDUP     = 63,
    DYNAMIC_TYPE_PRIVATE_KEY  = 64,
    DYNAMIC_TYPE_HMAC         = 65,
    DYNAMIC_TYPE_ASYNC        = 66,
    DYNAMIC_TYPE_ASYNC_NUMA   = 67,
    DYNAMIC_TYPE_ASYNC_NUMA64 = 68,
    DYNAMIC_TYPE_CURVE25519   = 69,
    DYNAMIC_TYPE_ED25519      = 70,
    DYNAMIC_TYPE_SECRET       = 71,
    DYNAMIC_TYPE_DIGEST       = 72,
    DYNAMIC_TYPE_RSA_BUFFER   = 73,
    DYNAMIC_TYPE_DCERT        = 74,
    DYNAMIC_TYPE_STRING       = 75,
    DYNAMIC_TYPE_PEM          = 76,
    DYNAMIC_TYPE_DER          = 77,
    DYNAMIC_TYPE_CERT_EXT     = 78,
    DYNAMIC_TYPE_ALPN         = 79,
    DYNAMIC_TYPE_ENCRYPTEDINFO= 80,
    DYNAMIC_TYPE_DIRCTX       = 81,
    DYNAMIC_TYPE_HASHCTX      = 82,
    DYNAMIC_TYPE_SEED         = 83,
    DYNAMIC_TYPE_SYMMETRIC_KEY= 84,
    DYNAMIC_TYPE_ECC_BUFFER   = 85,
    DYNAMIC_TYPE_QSH          = 86,
    DYNAMIC_TYPE_SALT         = 87,
    DYNAMIC_TYPE_HASH_TMP     = 88,
    DYNAMIC_TYPE_BLOB         = 89,
    DYNAMIC_TYPE_NAME_ENTRY   = 90,
};

#endif //WOLFSSL_RSAPSS_TYPES_H
