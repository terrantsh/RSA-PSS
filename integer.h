//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_INTEGER_H
#define WOLFSSL_RSAPSS_INTEGER_H

#include "types.h"

#define MP_OKAY       0   /* ok result */
#define MP_ZPOS       0   /* positive integer */
#define MP_VAL        -3  /* invalid input */
#define MP_PREC                 1      /* default digits of precision */
#define  OPT_CAST(x)
#define MP_MEM        -2  /* out of mem */
#define DIGIT_BIT          28
#define CHAR_BIT      8         // number of bits in a char
#define MAX_INVMOD_SZ 4096

typedef unsigned long long   ulong64;
typedef ulong64            mp_word;

#define MP_MASK          ((((mp_digit)1)<<((mp_digit)DIGIT_BIT))-((mp_digit)1))
#define mp_isodd(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1u) == 1u)) ? MP_YES : MP_NO)
#define mp_iseven(a) \
    (((a)->used > 0 && (((a)->dp[0] & 1u) == 0u)) ? MP_YES : MP_NO)
#define mp_iszero(a) (((a)->used == 0) ? MP_YES : MP_NO)
#define s_mp_mul(a, b, c) s_mp_mul_digs(a, b, c, (a)->used + (b)->used + 1)

/* size of comba arrays, should be at least 2 * 2**(BITS_PER_WORD - BITS_PER_DIGIT*2) */
#define MP_WARRAY  (1 << (sizeof(mp_word) * CHAR_BIT - 2 * DIGIT_BIT + 1))
#define MIN(x,y) ((x)<(y)?(x):(y))

/* equalities */
#define MP_LT        -1   /* less than */
#define MP_EQ         0   /* equal to */
#define MP_GT         1   /* greater than */

#define MP_ZPOS       0   /* positive integer */
#define MP_NEG        1   /* negative */

#define MP_OKAY       0   /* ok result */
#define MP_MEM        -2  /* out of mem */
#define MP_VAL        -3  /* invalid input */
#define MP_NOT_INF	  -4  /* point not at infinity */
#define MP_RANGE      MP_NOT_INF

#define MP_YES        1   /* yes response */
#define MP_NO         0   /* no response */

void mp_free (mp_int * a);
void mp_clear (mp_int * a);
int mp_init (mp_int * a);
int mp_init_multi(mp_int* a, mp_int* b, mp_int* c, mp_int* d, mp_int* e,mp_int* f);
int mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c);
int mp_cmp_d(mp_int * a, mp_digit b);
int mp_add_d (mp_int* a, mp_digit b, mp_int* c);
int mp_cmp (mp_int * a, mp_int * b);
void mp_zero (mp_int * a);
int mp_lshd (mp_int * a, int b);
int mp_invmod (mp_int * a, mp_int * b, mp_int * c);
int mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y);
int mp_mulmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d);
int mp_unsigned_bin_size (mp_int * a);
int mp_to_unsigned_bin_len(mp_int * a, unsigned char *b, int c);
int mp_sub (mp_int * a, mp_int * b, mp_int * c);
int mp_mul (mp_int * a, mp_int * b, mp_int * c);
int mp_add (mp_int * a, mp_int * b, mp_int * c);
int mp_count_bits (mp_int * a);
int s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs);



#endif //WOLFSSL_RSAPSS_INTEGER_H
