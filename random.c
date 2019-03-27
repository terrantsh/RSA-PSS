////
//// Created by Administrator on 2019/3/8.
////
//
#include "random.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"
#include "misc.h"

#define RESEED_INTERVAL   WC_RESEED_INTERVAL

int Hash_DRBG_Generate(DRBG* drbg, byte* out, word32 outSz);

/* Make sure compiler doesn't skip */
void ForceZero(const void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) *z++ = 0;
}

static int Hash_df(DRBG* drbg, byte* out, word32 outSz, byte type,
                   const byte* inA, word32 inASz,
                   const byte* inB, word32 inBSz)
{
    int ret = DRBG_FAILURE;
    byte ctr;
    int i;
    int len;
    word32 bits = (outSz * 8); /* reverse byte order */
#ifdef WOLFSSL_SMALL_STACK_CACHE
    wc_Sha256* sha = &drbg->sha256;
#else
    wc_Sha256 sha[1];
#endif

    byte digest[WC_SHA256_DIGEST_SIZE];
    (void)drbg;

#ifdef LITTLE_ENDIAN_ORDER
    bits = ByteReverseWord32(bits);
#endif
    len = (outSz / OUTPUT_BLOCK_LEN)
          + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    for (i = 0, ctr = 1; i < len; i++, ctr++) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
        ret = wc_InitSha256(sha);
        if (ret != 0)
            break;

        if (ret == 0)
#endif
            ret = wc_Sha256Update(sha, &ctr, sizeof(ctr));
        if (ret == 0)
            ret = wc_Sha256Update(sha, (byte*)&bits, sizeof(bits));

        if (ret == 0) {
            /* churning V is the only string that doesn't have the type added */
            if (type != drbgInitV)
                ret = wc_Sha256Update(sha, &type, sizeof(type));
        }
        if (ret == 0)
            ret = wc_Sha256Update(sha, inA, inASz);
        if (ret == 0) {
            if (inB != NULL && inBSz > 0)
                ret = wc_Sha256Update(sha, inB, inBSz);
        }
        if (ret == 0)
            ret = wc_Sha256Final(sha, digest);

        if (ret == 0) {
            if (outSz > OUTPUT_BLOCK_LEN) {
                XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
                outSz -= OUTPUT_BLOCK_LEN;
                out += OUTPUT_BLOCK_LEN;
            }
            else {
                XMEMCPY(out, digest, outSz);
            }
        }
    }

    ForceZero(digest, WC_SHA256_DIGEST_SIZE);
    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Instantiate(DRBG* drbg, const byte* seed, word32 seedSz,
                                 const byte* nonce, word32 nonceSz,
                                 void* heap, int devId)
{
    int ret = DRBG_FAILURE;

    XMEMSET(drbg, 0, sizeof(DRBG));
    (void)heap;
    (void)devId;

    if (Hash_df(drbg, drbg->V, sizeof(drbg->V), drbgInitV, seed, seedSz,
                nonce, nonceSz) == DRBG_SUCCESS &&
        Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                sizeof(drbg->V), NULL, 0) == DRBG_SUCCESS) {

        drbg->reseedCtr = 1;
        drbg->lastBlock = 0;
        drbg->matchCount = 0;
        ret = DRBG_SUCCESS;
    }

    return ret;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Reseed(DRBG* drbg, const byte* seed, word32 seedSz)
{
    byte newV[DRBG_SEED_LEN];

    XMEMSET(newV, 0, DRBG_SEED_LEN);

    if (Hash_df(drbg, newV, sizeof(newV), drbgReseed,
                drbg->V, sizeof(drbg->V), seed, seedSz) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    XMEMCPY(drbg->V, newV, sizeof(drbg->V));
    ForceZero(newV, sizeof(newV));

    if (Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                sizeof(drbg->V), NULL, 0) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    drbg->reseedCtr = 1;
    drbg->lastBlock = 0;
    drbg->matchCount = 0;
    return DRBG_SUCCESS;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Uninstantiate(DRBG* drbg)
{
    word32 i;
    int    compareSum = 0;
    byte*  compareDrbg = (byte*)drbg;


    ForceZero(drbg, sizeof(DRBG));

    for (i = 0; i < sizeof(DRBG); i++)
        compareSum |= compareDrbg[i] ^ 0;

    return (compareSum == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}


int wc_RNG_HealthTest_ex(int reseed, const byte* nonce, word32 nonceSz,
                         const byte* seedA, word32 seedASz,
                         const byte* seedB, word32 seedBSz,
                         byte* output, word32 outputSz,
                         void* heap, int devId)
{
    int ret = -1;
    DRBG* drbg;
    DRBG  drbg_var;

    if (seedA == NULL || output == NULL) {
        return BAD_FUNC_ARG;
    }

    if (reseed != 0 && seedB == NULL) {
        return BAD_FUNC_ARG;
    }

    if (outputSz != RNG_HEALTH_TEST_CHECK_SIZE) {
        return ret;
    }

//#ifdef WOLFSSL_SMALL_STACK
//    drbg = (DRBG*)XMALLOC(sizeof(DRBG), NULL, DYNAMIC_TYPE_RNG);
//    if (drbg == NULL) {
//        return MEMORY_E;
//    }
//#endif

    drbg = &drbg_var;

    if (Hash_DRBG_Instantiate(drbg, seedA, seedASz, nonce, nonceSz,
                              heap, devId) != 0) {
        goto exit_rng_ht;
    }

    if (reseed) {
        if (Hash_DRBG_Reseed(drbg, seedB, seedBSz) != 0) {
            goto exit_rng_ht;
        }
    }

    if (Hash_DRBG_Generate(drbg, output, outputSz) != 0) {
        goto exit_rng_ht;
    }

    if (Hash_DRBG_Generate(drbg, output, outputSz) != 0) {
        goto exit_rng_ht;
    }

    /* Mark success */
    ret = 0;
    exit_rng_ht:

    /* This is safe to call even if Hash_DRBG_Instantiate fails */
    if (Hash_DRBG_Uninstantiate(drbg) != 0) {
        ret = -1;
    }

    return ret;
}

int wc_RNG_HealthTest(int reseed, const byte* seedA, word32 seedASz,
                      const byte* seedB, word32 seedBSz,
                      byte* output, word32 outputSz)
{
    return wc_RNG_HealthTest_ex(reseed, NULL, 0,
                                seedA, seedASz, seedB, seedBSz,
                                output, outputSz,
                                NULL, INVALID_DEVID);
}


const byte seedA[] = {
        0x63, 0x36, 0x33, 0x77, 0xe4, 0x1e, 0x86, 0x46, 0x8d, 0xeb, 0x0a, 0xb4,
        0xa8, 0xed, 0x68, 0x3f, 0x6a, 0x13, 0x4e, 0x47, 0xe0, 0x14, 0xc7, 0x00,
        0x45, 0x4e, 0x81, 0xe9, 0x53, 0x58, 0xa5, 0x69, 0x80, 0x8a, 0xa3, 0x8f,
        0x2a, 0x72, 0xa6, 0x23, 0x59, 0x91, 0x5a, 0x9f, 0x8a, 0x04, 0xca, 0x68
};

const byte reseedSeedA[] = {
        0xe6, 0x2b, 0x8a, 0x8e, 0xe8, 0xf1, 0x41, 0xb6, 0x98, 0x05, 0x66, 0xe3,
        0xbf, 0xe3, 0xc0, 0x49, 0x03, 0xda, 0xd4, 0xac, 0x2c, 0xdf, 0x9f, 0x22,
        0x80, 0x01, 0x0a, 0x67, 0x39, 0xbc, 0x83, 0xd3
};

const byte outputA[] = {
        0x04, 0xee, 0xc6, 0x3b, 0xb2, 0x31, 0xdf, 0x2c, 0x63, 0x0a, 0x1a, 0xfb,
        0xe7, 0x24, 0x94, 0x9d, 0x00, 0x5a, 0x58, 0x78, 0x51, 0xe1, 0xaa, 0x79,
        0x5e, 0x47, 0x73, 0x47, 0xc8, 0xb0, 0x56, 0x62, 0x1c, 0x18, 0xbd, 0xdc,
        0xdd, 0x8d, 0x99, 0xfc, 0x5f, 0xc2, 0xb9, 0x20, 0x53, 0xd8, 0xcf, 0xac,
        0xfb, 0x0b, 0xb8, 0x83, 0x12, 0x05, 0xfa, 0xd1, 0xdd, 0xd6, 0xc0, 0x71,
        0x31, 0x8a, 0x60, 0x18, 0xf0, 0x3b, 0x73, 0xf5, 0xed, 0xe4, 0xd4, 0xd0,
        0x71, 0xf9, 0xde, 0x03, 0xfd, 0x7a, 0xea, 0x10, 0x5d, 0x92, 0x99, 0xb8,
        0xaf, 0x99, 0xaa, 0x07, 0x5b, 0xdb, 0x4d, 0xb9, 0xaa, 0x28, 0xc1, 0x8d,
        0x17, 0x4b, 0x56, 0xee, 0x2a, 0x01, 0x4d, 0x09, 0x88, 0x96, 0xff, 0x22,
        0x82, 0xc9, 0x55, 0xa8, 0x19, 0x69, 0xe0, 0x69, 0xfa, 0x8c, 0xe0, 0x07,
        0xa1, 0x80, 0x18, 0x3a, 0x07, 0xdf, 0xae, 0x17
};

const byte seedB[] = {
        0xa6, 0x5a, 0xd0, 0xf3, 0x45, 0xdb, 0x4e, 0x0e, 0xff, 0xe8, 0x75, 0xc3,
        0xa2, 0xe7, 0x1f, 0x42, 0xc7, 0x12, 0x9d, 0x62, 0x0f, 0xf5, 0xc1, 0x19,
        0xa9, 0xef, 0x55, 0xf0, 0x51, 0x85, 0xe0, 0xfb, /* nonce next */
        0x85, 0x81, 0xf9, 0x31, 0x75, 0x17, 0x27, 0x6e, 0x06, 0xe9, 0x60, 0x7d,
        0xdb, 0xcb, 0xcc, 0x2e
};

const byte outputB[] = {
        0xd3, 0xe1, 0x60, 0xc3, 0x5b, 0x99, 0xf3, 0x40, 0xb2, 0x62, 0x82, 0x64,
        0xd1, 0x75, 0x10, 0x60, 0xe0, 0x04, 0x5d, 0xa3, 0x83, 0xff, 0x57, 0xa5,
        0x7d, 0x73, 0xa6, 0x73, 0xd2, 0xb8, 0xd8, 0x0d, 0xaa, 0xf6, 0xa6, 0xc3,
        0x5a, 0x91, 0xbb, 0x45, 0x79, 0xd7, 0x3f, 0xd0, 0xc8, 0xfe, 0xd1, 0x11,
        0xb0, 0x39, 0x13, 0x06, 0x82, 0x8a, 0xdf, 0xed, 0x52, 0x8f, 0x01, 0x81,
        0x21, 0xb3, 0xfe, 0xbd, 0xc3, 0x43, 0xe7, 0x97, 0xb8, 0x7d, 0xbb, 0x63,
        0xdb, 0x13, 0x33, 0xde, 0xd9, 0xd1, 0xec, 0xe1, 0x77, 0xcf, 0xa6, 0xb7,
        0x1f, 0xe8, 0xab, 0x1d, 0xa4, 0x66, 0x24, 0xed, 0x64, 0x15, 0xe5, 0x1c,
        0xcd, 0xe2, 0xc7, 0xca, 0x86, 0xe2, 0x83, 0x99, 0x0e, 0xea, 0xeb, 0x91,
        0x12, 0x04, 0x15, 0x52, 0x8b, 0x22, 0x95, 0x91, 0x02, 0x81, 0xb0, 0x2d,
        0xd4, 0x31, 0xf4, 0xc9, 0xf7, 0x04, 0x27, 0xdf
};

STATIC WC_INLINE int ConstantCompare(const byte* a, const byte* b, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum;
}

STATIC WC_INLINE int wc_RNG_HealthTestLocal(int reseed)
{
    int ret = 0;
//#ifdef WOLFSSL_SMALL_STACK
//    byte* check;
//#endif
//
//#ifdef WOLFSSL_SMALL_STACK
//    check = (byte*)XMALLOC(RNG_HEALTH_TEST_CHECK_SIZE, NULL,
//                           DYNAMIC_TYPE_TMP_BUFFER);
//    if (check == NULL) {
//        return MEMORY_E;
//    }
//#endif

    byte  check[RNG_HEALTH_TEST_CHECK_SIZE];
    if (reseed) {
        ret = wc_RNG_HealthTest(1, seedA, sizeof(seedA), reseedSeedA, sizeof(reseedSeedA), check, RNG_HEALTH_TEST_CHECK_SIZE);
        if (ret == 0) {
            if (ConstantCompare(check, outputA, RNG_HEALTH_TEST_CHECK_SIZE) != 0)
                ret = -1;
        }
    } else {
        ret = wc_RNG_HealthTest(0, seedB, sizeof(seedB), NULL, 0, check, RNG_HEALTH_TEST_CHECK_SIZE);
        if (ret == 0) {
            if (ConstantCompare(check, outputB, RNG_HEALTH_TEST_CHECK_SIZE) != 0)
                ret = -1;
        }

        /* The previous test cases use a large seed instead of a seed and nonce.
         * seedB is actually from a test case with a seed and nonce, and
         * just concatenates them. The pivot point between seed and nonce is
         * byte 32, feed them into the health test separately. */
        if (ret == 0) {
            ret = wc_RNG_HealthTest_ex(0, seedB + 32, sizeof(seedB) - 32,  seedB, 32, NULL, 0, check, RNG_HEALTH_TEST_CHECK_SIZE, NULL, INVALID_DEVID);
            if (ret == 0) {
                if (ConstantCompare(check, outputB, sizeof(outputB)) != 0)
                    ret = -1;
            }
        }
    }
    return ret;
}

extern byte randseed;

// rand generator
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
	//you can use your own rand functuons here
	return 0;
}

int wc_RNG_TestSeed(const byte* seed, word32 seedSz)
{
    int ret = DRBG_SUCCESS;

    /* Check the seed for duplicate words. */
    word32 seedIdx = 0;
    word32 scratchSz = min(SEED_BLOCK_SZ, seedSz - SEED_BLOCK_SZ);

    while (seedIdx < seedSz - SEED_BLOCK_SZ) {
        if (ConstantCompare(seed + seedIdx,
                            seed + seedIdx + scratchSz,
                            scratchSz) == 0) {

            ret = DRBG_CONT_FAILURE;
        }
        seedIdx += SEED_BLOCK_SZ;
        scratchSz = min(SEED_BLOCK_SZ, (seedSz - seedIdx));
    }

    return ret;
}

static WC_INLINE void array_add_one(byte* data, word32 dataSz)
{
    int i;

    for (i = dataSz - 1; i >= 0; i--)
    {
        data[i]++;
        if (data[i] != 0) break;
    }
}

static int Hash_gen(DRBG* drbg, byte* out, word32 outSz, const byte* V)
{
    int ret = DRBG_FAILURE;
    byte data[DRBG_SEED_LEN];
    int i;
    int len;
    word32 checkBlock;
    wc_Sha256 sha[1];
    byte digest[WC_SHA256_DIGEST_SIZE];

    /* Special case: outSz is 0 and out is NULL. wc_Generate a block to save for
     * the continuous test. */

    if (outSz == 0) outSz = 1;

    len = (outSz / OUTPUT_BLOCK_LEN) + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    XMEMCPY(data, V, sizeof(data));
    for (i = 0; i < len; i++) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
        ret = wc_InitSha256(sha);
        if (ret == 0)
#endif
            ret = wc_Sha256Update(sha, data, sizeof(data));
        if (ret == 0)
            ret = wc_Sha256Final(sha, digest);

        if (ret == 0) {
            XMEMCPY(&checkBlock, digest, sizeof(word32));
            if (drbg->reseedCtr > 1 && checkBlock == drbg->lastBlock) {
                if (drbg->matchCount == 1) {
                    return DRBG_CONT_FAILURE;
                }
                else {
                    if (i == len) {
                        len++;
                    }
                    drbg->matchCount = 1;
                }
            }
            else {
                drbg->matchCount = 0;
                drbg->lastBlock = checkBlock;
            }

            if (out != NULL && outSz != 0) {
                if (outSz >= OUTPUT_BLOCK_LEN) {
                    XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
                    outSz -= OUTPUT_BLOCK_LEN;
                    out += OUTPUT_BLOCK_LEN;
                    array_add_one(data, DRBG_SEED_LEN);
                }
                else {
                    XMEMCPY(out, digest, outSz);
                    outSz = 0;
                }
            }
        }
    }
    ForceZero(data, sizeof(data));

    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

static WC_INLINE void array_add(byte* d, word32 dLen, const byte* s, word32 sLen)
{
    word16 carry = 0;

    if (dLen > 0 && sLen > 0 && dLen >= sLen) {
        int sIdx, dIdx;

        for (sIdx = sLen - 1, dIdx = dLen - 1; sIdx >= 0; dIdx--, sIdx--)
        {
            carry += d[dIdx] + s[sIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }

        for (; carry != 0 && dIdx >= 0; dIdx--) {
            carry += d[dIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }
    }
}

int Hash_DRBG_Generate(DRBG* drbg, byte* out, word32 outSz)
{
    int ret;
    wc_Sha256 sha[1];
    byte type;
    word32 reseedCtr;

    if (drbg->reseedCtr == RESEED_INTERVAL) {
        return DRBG_NEED_RESEED;
    } else {

        byte digest[WC_SHA256_DIGEST_SIZE];

        type = drbgGenerateH;
        reseedCtr = drbg->reseedCtr;

        ret = Hash_gen(drbg, out, outSz, drbg->V);
        if (ret == DRBG_SUCCESS) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
            ret = wc_InitSha256(sha);
            if (ret == 0)
#endif
                ret = wc_Sha256Update(sha, &type, sizeof(type));
            if (ret == 0)
                ret = wc_Sha256Update(sha, drbg->V, sizeof(drbg->V));
            if (ret == 0)
                ret = wc_Sha256Final(sha, digest);

            if (ret == 0) {
                array_add(drbg->V, sizeof(drbg->V), digest, WC_SHA256_DIGEST_SIZE);
                array_add(drbg->V, sizeof(drbg->V), drbg->C, sizeof(drbg->C));
#ifdef LITTLE_ENDIAN_ORDER
//                reseedCtr = ByteReverseWord32(reseedCtr);
#endif
                array_add(drbg->V, sizeof(drbg->V),
                          (byte*)&reseedCtr, sizeof(reseedCtr));
                ret = DRBG_SUCCESS;
            }
            drbg->reseedCtr++;
        }
        ForceZero(digest, WC_SHA256_DIGEST_SIZE);
    }

    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

static int _InitRng(WC_RNG* rng, byte* nonce, word32 nonceSz, void* heap, int devId)
{
    int ret = RNG_FAILURE_E;
#ifdef HAVE_HASHDRBG
    word32 seedSz = SEED_SZ + SEED_BLOCK_SZ;
#endif

    (void)nonce;
    (void)nonceSz;
    int rngdrbg[30] = {0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd,0xcdcdcdcd};

    if (rng == NULL)
        return BAD_FUNC_ARG;
    if (nonce == NULL && nonceSz != 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_HEAP_TEST
#else
    rng->heap = heap;
#endif

#ifdef HAVE_HASHDRBG
    /* init the DBRG to known values */
    rng->drbg = NULL;
    rng->status = DRBG_NOT_INIT;
#endif

#ifdef HAVE_HASHDRBG
    if (nonceSz == 0)
        seedSz = MAX_SEED_SZ;

    if (wc_RNG_HealthTestLocal(0) == 0) {
        byte seed[MAX_SEED_SZ];
        rng->drbg = rngdrbg;
//        rng->drbg = (struct DRBG*)XMALLOC(sizeof(DRBG), rng->heap, DYNAMIC_TYPE_RNG);
        if (rng->drbg == NULL) {
            ret = MEMORY_E;
        }
        else {
            ret = wc_GenerateSeed(&rng->seed, seed, seedSz);
            if (ret != 0)
                ret = DRBG_FAILURE;
            else
                ret = wc_RNG_TestSeed(seed, seedSz);

            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Instantiate(rng->drbg,
                                            seed + SEED_BLOCK_SZ, seedSz - SEED_BLOCK_SZ,
                                            nonce, nonceSz, rng->heap, devId);

            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Generate(rng->drbg, NULL, 0);
        }

        ForceZero(seed, seedSz);
    }
    else
        ret = DRBG_CONT_FAILURE;

    if (ret == DRBG_SUCCESS) {
        rng->status = DRBG_OK;
        ret = 0;
    }
    else if (ret == DRBG_CONT_FAILURE) {
        rng->status = DRBG_CONT_FAILED;
        ret = DRBG_CONT_FIPS_E;
    }
    else if (ret == DRBG_FAILURE) {
        rng->status = DRBG_FAILED;
        ret = RNG_FAILURE_E;
    }
    else {
        rng->status = DRBG_FAILED;
    }
#endif /* HAVE_HASHDRBG */

    return ret;
}

int wc_InitRng(WC_RNG* rng)
{
    return _InitRng(rng, NULL, 0, NULL, INVALID_DEVID);
}

/* place a generated block in output */
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    int ret;

    if (rng == NULL || output == NULL)
        return BAD_FUNC_ARG;
    if (sz > RNG_MAX_BLOCK_LEN)
        return BAD_FUNC_ARG;

    if (rng->status != DRBG_OK)
        return RNG_FAILURE_E;

    ret = Hash_DRBG_Generate(rng->drbg, output, sz);
    if (ret == DRBG_NEED_RESEED) {
        if (wc_RNG_HealthTestLocal(1) == 0) {
            byte newSeed[SEED_SZ + SEED_BLOCK_SZ];

            ret = wc_GenerateSeed(&rng->seed, newSeed,
                                  SEED_SZ + SEED_BLOCK_SZ);
            if (ret != 0)
                ret = DRBG_FAILURE;
            else
                ret = wc_RNG_TestSeed(newSeed, SEED_SZ + SEED_BLOCK_SZ);

            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Reseed(rng->drbg, newSeed + SEED_BLOCK_SZ,
                                       SEED_SZ);
            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Generate(rng->drbg, NULL, 0);
            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Generate(rng->drbg, output, sz);

            ForceZero(newSeed, sizeof(newSeed));
        }
        else
            ret = DRBG_CONT_FAILURE;
    }

    if (ret == DRBG_SUCCESS) {
        ret = 0;
    }
    else if (ret == DRBG_CONT_FAILURE) {
        ret = DRBG_CONT_FIPS_E;
        rng->status = DRBG_CONT_FAILED;
    }
    else {
        ret = RNG_FAILURE_E;
        rng->status = DRBG_FAILED;
    }
    return ret;
}
