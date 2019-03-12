//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_SHA256_H
#define WOLFSSL_RSAPSS_SHA256_H

#include "types.h"
#include "error.h"
#pragma once
#include <stdint.h>
#include <stdio.h>

typedef struct{
    uint64_t    length;
    uint32_t    state[8];
    uint32_t    curlen;
    uint8_t     buf[64];
} wc_Sha256;
#define SHA256_HASH_SIZE           ( 256 / 8 )

typedef struct{
    //uint8_t      bytes [SHA256_HASH_SIZE];
    uint8_t bytes [SHA256_HASH_SIZE];
} SHA256_HASH;

/* in bytes */
enum {
    WC_SHA256              =  WC_HASH_TYPE_SHA256,
    WC_SHA256_BLOCK_SIZE   = 64,
    WC_SHA256_DIGEST_SIZE  = 32,
    WC_SHA256_PAD_SIZE     = 56
};

int wc_InitSha256(wc_Sha256* Context);        // [out]
int wc_Sha256Update(wc_Sha256* Context, void const* Buffer, uint32_t BufferSize);        // [in out][in][in]
int wc_Sha256Final(wc_Sha256* Context,  byte* Digest);       // [in out][out]

#endif //WOLFSSL_RSAPSS_SHA256_H
