//
// Created by Administrator on 2019/3/8.
//

#include "rsa.h"
#include "error.h"
#include "integer.h"
#include "wolfmath.h"
#include "misc.h"

int wc_RsaEncryptSize(RsaKey* key)
{
    int ret;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = mp_unsigned_bin_size(&key->n);
    return ret;
}

static int wc_RsaFunctionSync(const byte* in, word32 inLen, byte* out, word32* outLen, int type, RsaKey* key, WC_RNG* rng)
{
    mp_int tmp[1];
    mp_int rnd[1], rndi[1];
    int    ret = 0;
    word32 keyLen = 0;
    (void)rng;
    if (mp_init(tmp) != MP_OKAY)
        ret = MP_INIT_E;
#ifdef WC_RSA_BLINDING
    if (ret == 0) {
        if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
            if (mp_init_multi(rnd, rndi, NULL, NULL, NULL, NULL) != MP_OKAY) {
                mp_clear(tmp);
                ret = MP_INIT_E;
            }
        }
    }
#endif
#ifndef TEST_UNPAD_CONSTANT_TIME
    if (ret == 0 && mp_read_unsigned_bin(tmp, (byte*)in, inLen) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0) {
        switch(type) {
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
            case RSA_PRIVATE_DECRYPT:
            case RSA_PRIVATE_ENCRYPT:
            {
#if defined(WC_RSA_BLINDING) && !defined(WC_NO_RNG)
                /* blind */
                ret = mp_rand(rnd, get_digit_count(&key->n), rng);

                /* rndi = 1/rnd mod n */
                if (ret == 0 && mp_invmod(rnd, &key->n, rndi) != MP_OKAY)
                    ret = MP_INVMOD_E;

                /* rnd = rnd^e */
                if (ret == 0 && mp_exptmod(rnd, &key->e, &key->n, rnd) != MP_OKAY)
                    ret = MP_EXPTMOD_E;

                /* tmp = tmp*rnd mod n */
                if (ret == 0 && mp_mulmod(tmp, rnd, &key->n, tmp) != MP_OKAY)
                    ret = MP_MULMOD_E;
#endif /* WC_RSA_BLINDING && !WC_NO_RNG */
#ifdef RSA_LOW_MEM      /* half as much memory but twice as slow */
#else
                if (ret == 0) {
                    mp_int tmpa[1], tmpb[1];
                    int cleara = 0, clearb = 0;

                    if (ret == 0) {
                        if (mp_init(tmpa) != MP_OKAY)
                            ret = MP_INIT_E;
                        else
                            cleara = 1;
                    }
                    if (ret == 0) {
                        if (mp_init(tmpb) != MP_OKAY)
                            ret = MP_INIT_E;
                        else
                            clearb = 1;
                    }
                    /* tmpa = tmp^dP mod p */
                    if (ret == 0 && mp_exptmod(tmp, &key->dP, &key->p, tmpa) != MP_OKAY)
                        ret = MP_EXPTMOD_E;

                    /* tmpb = tmp^dQ mod q */
                    if (ret == 0 && mp_exptmod(tmp, &key->dQ, &key->q,
                                               tmpb) != MP_OKAY)
                        ret = MP_EXPTMOD_E;

                    /* tmp = (tmpa - tmpb) * qInv (mod p) */
                    if (ret == 0 && mp_sub(tmpa, tmpb, tmp) != MP_OKAY)
                        ret = MP_SUB_E;

                    if (ret == 0 && mp_mulmod(tmp, &key->u, &key->p,
                                              tmp) != MP_OKAY)
                        ret = MP_MULMOD_E;

                    /* tmp = tmpb + q * tmp */
                    if (ret == 0 && mp_mul(tmp, &key->q, tmp) != MP_OKAY)
                        ret = MP_MUL_E;

                    if (ret == 0 && mp_add(tmp, tmpb, tmp) != MP_OKAY)
                        ret = MP_ADD_E;

                    {
                        if (cleara)
                            mp_clear(tmpa);
                        if (clearb)
                            mp_clear(tmpb);
                    }
                } /* tmpa/b scope */
#endif   /* RSA_LOW_MEM */
#ifdef WC_RSA_BLINDING
                /* unblind */
                if (ret == 0 && mp_mulmod(tmp, rndi, &key->n, tmp) != MP_OKAY)
                    ret = MP_MULMOD_E;
#endif   /* WC_RSA_BLINDING */
                break;
            }
#endif
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PUBLIC_DECRYPT:
                if (mp_exptmod(tmp, &key->e, &key->n, tmp) != MP_OKAY)
                    ret = MP_EXPTMOD_E;
                break;
            default:
                ret = RSA_WRONG_TYPE_E;
                break;
        }
    }
    if (ret == 0) {
        keyLen = wc_RsaEncryptSize(key);
        if (keyLen > *outLen)
            ret = RSA_BUFFER_E;
    }
    if (ret == 0) {
        *outLen = keyLen;
        if (mp_to_unsigned_bin_len(tmp, out, keyLen) != MP_OKAY)
            ret = MP_TO_E;
    }
#endif
    mp_clear(tmp);
#ifdef WC_RSA_BLINDING
    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
        mp_clear(rndi);
        mp_clear(rnd);
    }

#endif /* WC_RSA_BLINDING */
    return ret;
}

int wc_RsaFunction(const byte* in, word32 inLen, byte* out,
                   word32* outLen, int type, RsaKey* key, WC_RNG* rng)
{
    int ret = 0;

    if (key == NULL || in == NULL || inLen == 0 || out == NULL ||
        outLen == NULL || *outLen == 0 || type == RSA_TYPE_UNKNOWN) {
        return BAD_FUNC_ARG;
    }
    if (type == RSA_PRIVATE_DECRYPT &&
        key->state == RSA_STATE_DECRYPT_EXPTMOD) {

        /* Check that 1 < in < n-1. (Requirement of 800-56B.) */
        mp_int c[1];

        if (mp_init(c) != MP_OKAY)
            ret = MEMORY_E;
        if (ret == 0) {
            if (mp_read_unsigned_bin(c, in, inLen) != 0)
                ret = MP_READ_E;
        }
        if (ret == 0) {
            /* check c > 1 */
            if (mp_cmp_d(c, 1) != MP_GT)
                ret = RSA_OUT_OF_RANGE_E;
        }
        if (ret == 0) {
            /* add c+1 */
            if (mp_add_d(c, 1, c) != MP_OKAY)
                ret = MP_ADD_E;
        }
        if (ret == 0) {
            /* check c+1 < n */
            if (mp_cmp(c, &key->n) != MP_LT)
                ret = RSA_OUT_OF_RANGE_E;
        }
        mp_clear(c);
        if (ret != 0)
            return ret;
    }
    {
        ret = wc_RsaFunctionSync(in, inLen, out, outLen, type, key, rng);
    }
    /* handle error */
    if (ret < 0 && ret != WC_PENDING_E
            ) {
        if (ret == MP_EXPTMOD_E) {
            /* This can happen due to incorrectly set FP_MAX_BITS or missing XREALLOC */
        }
        key->state = RSA_STATE_NONE;
    }

    return ret;
}

static int RsaMGF1(enum wc_HashType hType, byte* seed, word32 seedSz,
                   byte* out, word32 outSz, void* heap)
{
    byte* tmp;
    /* needs to be large enough for seed size plus counter(4) */
    byte  tmpA[WC_MAX_DIGEST_SIZE + 4];
    byte   tmpF;     /* 1 if dynamic memory needs freed */
    word32 tmpSz;
    int hLen;
    int ret;
    word32 counter;
    word32 idx;
    hLen    = wc_HashGetDigestSize(hType);
    counter = 0;
    idx     = 0;

    (void)heap;
    /* check error return of wc_HashGetDigestSize */
    if (hLen < 0) {
        return hLen;
    }
    /* if tmp is not large enough than use some dynamic memory */
    if ((seedSz + 4) > sizeof(tmpA) || (word32)hLen > sizeof(tmpA)) {
        /* find largest amount of memory needed which will be the max of
         * hLen and (seedSz + 4) since tmp is used to store the hash digest */
        tmpSz = ((seedSz + 4) > (word32)hLen)? seedSz + 4: (word32)hLen;
        tmp = (byte*)XMALLOC(tmpSz, heap, DYNAMIC_TYPE_RSA_BUFFER);
        if (tmp == NULL) {
            return MEMORY_E;
        }
        tmpF = 1; /* make sure to free memory when done */
    }
    else {
        /* use array on the stack */
        tmpSz = sizeof(tmpA);
        tmp  = tmpA;
        tmpF = 0; /* no need to free memory at end */
    }

    do {
        int i = 0;
        XMEMCPY(tmp, seed, seedSz);

        /* counter to byte array appended to tmp */
        tmp[seedSz]     = (counter >> 24) & 0xFF;
        tmp[seedSz + 1] = (counter >> 16) & 0xFF;
        tmp[seedSz + 2] = (counter >>  8) & 0xFF;
        tmp[seedSz + 3] = (counter)       & 0xFF;

        /* hash and append to existing output */
        if ((ret = wc_Hash(hType, tmp, (seedSz + 4), tmp, tmpSz)) != 0) {
            /* check for if dynamic memory was needed, then free */
            if (tmpF) {
            }
            return ret;
        }

        for (i = 0; i < hLen && idx < outSz; i++) {
            out[idx++] = tmp[i];
        }
        counter++;
    } while (idx < outSz);

    /* check for if dynamic memory was needed, then free */
    if (tmpF) {
    }

    return 0;
}

static int RsaMGF(int type, byte* seed, word32 seedSz, byte* out,
                  word32 outSz, void* heap)
{
    int ret;

    switch(type) {
#ifndef NO_SHA256
        case WC_MGF1SHA256:
            ret = RsaMGF1(WC_HASH_TYPE_SHA256, seed, seedSz, out, outSz, heap);
            break;
#endif
        default:
            ret = BAD_FUNC_ARG;
    }
    /* in case of default avoid unused warning */
    (void)seed;
    (void)seedSz;
    (void)out;
    (void)outSz;
    (void)heap;
    return ret;
}

static int RsaUnPad_PSS(byte *pkcsBlock, unsigned int pkcsBlockLen,
                        byte **output, enum wc_HashType hType, int mgf,
                        int saltLen, int bits, void* heap)
{
    int   ret;
    byte* tmp;
    int   hLen, i;

    hLen = wc_HashGetDigestSize(hType);
    if (hLen < 0)
        return hLen;

    if (saltLen == -1) {
        saltLen = hLen;
    }
    else if (saltLen > hLen || saltLen < -1)
        return PSS_SALTLEN_E;
    if ((int)pkcsBlockLen - hLen < saltLen + 2)
        return PSS_SALTLEN_E;

    if (pkcsBlock[pkcsBlockLen - 1] != RSA_PSS_PAD_TERM) {
        return BAD_PADDING_E;
    }

    tmp = (byte*)XMALLOC(pkcsBlockLen, heap, DYNAMIC_TYPE_RSA_BUFFER);
    if (tmp == NULL)
        return MEMORY_E;

    if ((ret = RsaMGF(mgf, pkcsBlock + pkcsBlockLen - 1 - hLen, hLen,
                      tmp, pkcsBlockLen - 1 - hLen, heap)) != 0) {
        return ret;
    }

    tmp[0] &= (1 << ((bits - 1) & 0x7)) - 1;
    for (i = 0; i < (int)(pkcsBlockLen - 1 - saltLen - hLen - 1); i++) {
        if (tmp[i] != pkcsBlock[i]) {
            return BAD_PADDING_E;
        }
    }
    if (tmp[i] != (pkcsBlock[i] ^ 0x01)) {
        return BAD_PADDING_E;
    }
    for (i++; i < (int)(pkcsBlockLen - 1 - hLen); i++)
        pkcsBlock[i] ^= tmp[i];

    *output = pkcsBlock + pkcsBlockLen - (hLen + saltLen + 1);
    return saltLen + hLen;
}

static int wc_RsaUnPad_ex(byte* pkcsBlock, word32 pkcsBlockLen, byte** out, byte padValue, int padType, enum wc_HashType hType, int mgf, byte* optLabel, word32 labelLen, int saltLen, int bits, void* heap)
{
    int ret;
    switch (padType) {
#ifdef WC_RSA_PSS
        case WC_RSA_PSS_PAD:
            ret = RsaUnPad_PSS((byte*)pkcsBlock, pkcsBlockLen, out, hType, mgf,
                                                           saltLen, bits, heap);
            break;
#endif
        default:
            ret = RSA_PAD_E;
    }
    /* silence warning if not used with padding scheme */
    (void)hType;
    (void)mgf;
    (void)optLabel;
    (void)labelLen;
    (void)saltLen;
    (void)bits;
    (void)heap;

    return ret;
}

static int  RsaPrivateDecryptEx(byte* in, word32 inLen, byte* out,
                                word32 outLen, byte** outPtr, RsaKey* key,
                                int rsa_type, byte pad_value, int pad_type,
                                enum wc_HashType hash, int mgf,
                                byte* label, word32 labelSz, int saltLen,
                                WC_RNG* rng)
{
    int ret = RSA_WRONG_TYPE_E;

    if (in == NULL || inLen == 0 || out == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (key->state) {
        case RSA_STATE_NONE:
            key->dataLen = inLen;

            key->state = RSA_STATE_DECRYPT_EXPTMOD;
            FALL_THROUGH;

        case RSA_STATE_DECRYPT_EXPTMOD:

            ret = wc_RsaFunction(out, inLen, out, &key->dataLen, rsa_type, key, rng);

            if (ret >= 0 || ret == WC_PENDING_E) {
                key->state = RSA_STATE_DECRYPT_UNPAD;
            }
            if (ret < 0) {
                break;
            }

            FALL_THROUGH;

        case RSA_STATE_DECRYPT_UNPAD:
        {
            byte* pad = NULL;
            ret = wc_RsaUnPad_ex(out, key->dataLen, &pad, pad_value, pad_type, hash,
                             mgf, label, labelSz, saltLen,
                             mp_count_bits(&key->n), key->heap);

            if (rsa_type == RSA_PUBLIC_DECRYPT && ret > (int)outLen)
                ret = RSA_BUFFER_E;
            else if (ret >= 0 && pad != NULL) {
#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
                signed char c;
#endif
                /* only copy output if not inline */
                if (outPtr == NULL) {
                    word32 i, j;
                    int start = (int)((size_t)pad - (size_t)key->data);

                    for (i = 0, j = 0; j < key->dataLen; j++) {
                        out[i] = key->data[j];
                        c  = ctMaskGTE(j, start);
                        c &= ctMaskLT(i, outLen);
                        /* 0 - no add, -1 add */
                        i += -c;
                    }
                }
                else
                    *outPtr = pad;

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
                ret = ctMaskSelInt(ctMaskLTE(ret, outLen), ret, RSA_BUFFER_E);
                ret = ctMaskSelInt(ctMaskNotEq(ret, 0), ret, RSA_BUFFER_E);
#endif
            }
            key->state = RSA_STATE_DECRYPT_RES;
            FALL_THROUGH;
        }
        case RSA_STATE_DECRYPT_RES:
            break;
        default:
            ret = BAD_STATE_E;
            break;
    }
    /* if async pending then return and skip done cleanup below */
    if (ret == WC_PENDING_E
            ) {
        return ret;
    }
    key->state = RSA_STATE_NONE;
    return ret;
}

int wc_RsaPSS_VerifyInline_ex(byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf, int saltLen, RsaKey* key)
{
    WC_RNG* rng = NULL;
#ifdef WC_RSA_BLINDING
    rng = key->rng;
#endif
    return RsaPrivateDecryptEx(in, inLen, in, inLen, out, key, RSA_PUBLIC_DECRYPT, RSA_BLOCK_TYPE_1, WC_RSA_PSS_PAD, hash, mgf, NULL, 0, saltLen, rng);
}

int wc_RsaSetRNG(RsaKey* key, WC_RNG* rng)
{
    if (key == NULL)
        return BAD_FUNC_ARG;
    key->rng = rng;
    return 0;
}

int wc_InitRsaKey_ex(RsaKey* key, void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(key, 0, sizeof(RsaKey));

    key->type = RSA_TYPE_UNKNOWN;
    key->state = RSA_STATE_NONE;
    key->heap = heap;
#ifndef WOLFSSL_RSA_VERIFY_INLINE
    key->dataIsAlloc = 0;
    key->data = NULL;
#endif
    key->dataLen = 0;
#ifdef WC_RSA_BLINDING
    key->rng = NULL;
#endif

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    ret = mp_init_multi(&key->n, &key->e, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY)
        return ret;
    ret = mp_init_multi(&key->d, &key->p, &key->q, &key->dP, &key->dQ, &key->u);
    if (ret != MP_OKAY) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ret;
    }
#endif
    return ret;
}

int wc_InitRsaKey(RsaKey* key, void* heap)
{
    return wc_InitRsaKey_ex(key, heap, INVALID_DEVID);
}

int wc_RsaPSS_CheckPadding_ex(const byte* in, word32 inSz, byte* sig, word32 sigSz, enum wc_HashType hashType, int saltLen, int bits)
{
    int ret = 0;
    byte sigCheck[WC_SHA256_DIGEST_SIZE *2 + RSA_PSS_PAD_SZ]; //change WC_MAX_DIGEST_SIZE to WC_SHA256_DIGEST_SIZE

    (void)bits;

    if (in == NULL || sig == NULL ||
        inSz != (word32)wc_HashGetDigestSize(hashType))
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        if (saltLen == -1) {
            saltLen = inSz;
        }
        else if (saltLen < -1 || (word32)saltLen > inSz)
            ret = PSS_SALTLEN_E;
    }

    /* Sig = Salt | Exp Hash */
    if (ret == 0) {
        if (sigSz != inSz + saltLen)
            ret = BAD_PADDING_E;
    }

    /* Exp Hash = HASH(8 * 0x00 | Message Hash | Salt) */
    if (ret == 0) {
        XMEMSET(sigCheck, 0, RSA_PSS_PAD_SZ);
        XMEMCPY(sigCheck + RSA_PSS_PAD_SZ, in, inSz);
        XMEMCPY(sigCheck + RSA_PSS_PAD_SZ + inSz, sig, saltLen);
        ret = wc_Hash(hashType, sigCheck, RSA_PSS_PAD_SZ + inSz + saltLen, sigCheck, inSz);
    }
    if (ret == 0) {
        if (ret = XMEMCMP(sigCheck, sig + saltLen, inSz) != 0) {
            ret = BAD_PADDING_E;
        }
    }
    return ret;
}