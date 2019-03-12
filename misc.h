//
// Created by Administrator on 2019/3/11.
//

#ifndef WOLFSSL_RSAPSS_MISC_H
#define WOLFSSL_RSAPSS_MISC_H

#include "types.h"

word32 ByteReverseWord32(word32);
byte ctMaskLT(int a, int b);
byte ctMaskLTE(int a, int b);
byte ctMaskGTE(int a, int b);
byte ctMaskNotEq(int a, int b);
int ctMaskSelInt(byte m, int a, int b);

#endif //WOLFSSL_RSAPSS_MISC_H
