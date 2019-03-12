//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_RANDOM_H
#define WOLFSSL_RSAPSS_RANDOM_H

#include "types.h"
#include "error.h"
#include "sha256.h"

/* RNG health states */
#define DRBG_NOT_INIT                       0
#define DRBG_OK                             1
#define DRBG_FAILED                         2
#define DRBG_CONT_FAILED                    3
#define DRBG_FAILURE                        1
#define DRBG_SUCCESS                        0
#define HAVE_HASHDRBG
#define WC_RESEED_INTERVAL                  (1000000)
#define RNG_MAX_BLOCK_LEN                   (0x10000)
/* Internal return codes */
#define DRBG_NEED_RESEED                    2
#define DRBG_CONT_FAILURE                   3
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define RNG_HEALTH_TEST_CHECK_SIZE          (32 * 4)
#define RNG_SECURITY_STRENGTH               (256)
#define ENTROPY_SCALE_FACTOR                1
#define SEED_BLOCK_SZ                       4
#define SEED_SZ                             (RNG_SECURITY_STRENGTH*ENTROPY_SCALE_FACTOR/8)
#define MAX_SEED_SZ                         (SEED_SZ + SEED_SZ/2 + SEED_BLOCK_SZ)
#define DRBG_SEED_LEN                       (440/8)
#define OUTPUT_BLOCK_LEN                    (WC_SHA256_DIGEST_SIZE)

enum {
    drbgInitC     = 0,
    drbgReseed    = 1,
    drbgGenerateW = 2,
    drbgGenerateH = 3,
    drbgInitV
};

/* OS specific seeder */
typedef struct OS_Seed {
    ProviderHandle handle;
} OS_Seed;

/* RNG context */
struct WC_RNG {
    OS_Seed seed;
    void* heap;
#ifdef HAVE_HASHDRBG
    /* Hash-based Deterministic Random Bit Generator */
    struct DRBG* drbg;
    byte status;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
    int devId;
#endif
};

typedef struct DRBG {
    word32 reseedCtr;
    word32 lastBlock;
    byte V[DRBG_SEED_LEN];
    byte C[DRBG_SEED_LEN];
#ifdef WOLFSSL_ASYNC_CRYPT
    void* heap;
    int devId;
#endif
    byte   matchCount;
#ifdef WOLFSSL_SMALL_STACK_CACHE
    wc_Sha256 sha256;
#endif
} DRBG;

int wc_InitRng(WC_RNG* rng);
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);

#endif //WOLFSSL_RSAPSS_RANDOM_H
