//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_RSA_H
#define WOLFSSL_RSAPSS_RSA_H

#include "types.h"
#include "Tfm.h"
#include "random.h"
#include "hash.h"
#include "error.h"
#include "wolfmath.h"
#include "misc.h"

#define WC_MGF1SHA256        1
#define WC_RSA_PSS_PAD       2

enum {
    RSA_PUBLIC   = 0,
    RSA_PRIVATE  = 1,

    RSA_TYPE_UNKNOWN    = -1,
    RSA_PUBLIC_ENCRYPT  = 0,
    RSA_PUBLIC_DECRYPT  = 1,
    RSA_PRIVATE_ENCRYPT = 2,
    RSA_PRIVATE_DECRYPT = 3,

    RSA_BLOCK_TYPE_1 = 1,
    RSA_BLOCK_TYPE_2 = 2,

    RSA_MIN_PAD_SZ   = 11,     /* separator + 0 + pad value + 8 pads */

    RSA_PSS_PAD_SZ = 8,
    RSA_PSS_SALT_MAX_SZ = 62,

    RSA_PSS_PAD_TERM = 0xBC,
};

enum {
    RSA_STATE_NONE = 0,

    RSA_STATE_ENCRYPT_PAD,
    RSA_STATE_ENCRYPT_EXPTMOD,
    RSA_STATE_ENCRYPT_RES,

    RSA_STATE_DECRYPT_EXPTMOD,
    RSA_STATE_DECRYPT_UNPAD,
    RSA_STATE_DECRYPT_RES,
};

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

int wc_RsaEncryptSize(RsaKey* key);
int wc_InitRsaKey(RsaKey* key, void* heap);
int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng);
int wc_InitRsaKey_ex(RsaKey* key, void* heap, int devId);
int wc_RsaPSS_VerifyInline_ex(byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf, int saltLen, RsaKey* key);
int wc_RsaPSS_CheckPadding_ex(const byte* in, word32 inSz, byte* sig, word32 sigSz, enum wc_HashType hashType, int saltLen, int bits);


#endif //WOLFSSL_RSAPSS_RSA_H
