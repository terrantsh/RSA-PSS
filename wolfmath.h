//
// Created by Administrator on 2019/3/11.
//

#ifndef WOLFSSL_RSAPSS_WOLFMATH_H
#define WOLFSSL_RSAPSS_WOLFMATH_H

#include "types.h"
#include "error.h"
#include "integer.h"
#include "random.h"

int get_digit_count(mp_int* a);
int mp_rand(mp_int* a, int digits, WC_RNG* rng);

#endif //WOLFSSL_RSAPSS_WOLFMATH_H
