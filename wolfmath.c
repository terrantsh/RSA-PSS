//
// Created by Administrator on 2019/3/11.
//

#include "wolfmath.h"

int get_digit_count(mp_int* a)
{
    if (a == NULL) {
        return 0;
    }
    return a->used;
}

int get_rand_digit(WC_RNG* rng, mp_digit* d)
{
    return wc_RNG_GenerateBlock(rng, (byte*)d, sizeof(mp_digit));
}

int mp_rand(mp_int* a, int digits, WC_RNG* rng)
{
    int ret = 0;
    DECLARE_VAR(d, mp_digit, 1, rng ? rng->heap : NULL);

    if (rng == NULL) {
        ret = MISSING_RNG_E; goto exit;
    }

    if (a == NULL) {
        ret = BAD_FUNC_ARG; goto exit;
    }

    mp_zero(a);
    if (digits <= 0) {
        ret = MP_OKAY; goto exit;
    }

    /* first place a random non-zero digit */
    do {
        ret = get_rand_digit(rng, d);
        if (ret != 0) {
            goto exit;
        }
    } while (*d == 0);

    if ((ret = mp_add_d(a, *d, a)) != MP_OKAY) {
        goto exit;
    }

    while (--digits > 0) {
        if ((ret = mp_lshd(a, 1)) != MP_OKAY) {
            goto exit;
        }
        if ((ret = get_rand_digit(rng, d)) != 0) {
            goto exit;
        }
        if ((ret = mp_add_d(a, *d, a)) != MP_OKAY) {
            goto exit;
        }
    }

    exit:
    FREE_VAR(d, rng ? rng->heap : NULL);

    return ret;
}