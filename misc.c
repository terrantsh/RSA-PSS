//
// Created by Administrator on 2019/3/11.
//

#include "misc.h"
#include <stdlib.h>

STATIC WC_INLINE word32 rotlFixed(word32 x, word32 y)
{
    return y ? _lrotl(x, y) : x;
}

STATIC WC_INLINE word32 rotrFixed(word32 x, word32 y)
{
    return y ? _lrotr(x, y) : x;
}

WC_INLINE word32 ByteReverseWord32(word32 value)
{

    /* 5 instructions with rotate instruction, 9 without */
    return (rotrFixed(value, 8U) & 0xff00ff00) |
           (rotlFixed(value, 8U) & 0x00ff00ff);
}

/* Constant time - mask set when a >= b. */
WC_INLINE byte ctMaskGTE(int a, int b)
{
    return (((word32)a - b    ) >> 31) - 1;
}

/* Constant time - mask set when a < b. */
WC_INLINE byte ctMaskLT(int a, int b)
{
    return (((word32)b - a - 1) >> 31) - 1;
}

/* Constant time - select integer a when mask is set and integer b otherwise. */
WC_INLINE int ctMaskSelInt(byte m, int a, int b)
{
    return (b & (~(signed int)(signed char)m)) |
           (a & ( (signed int)(signed char)m));
}

/* Constant time - mask set when a <= b. */
WC_INLINE byte ctMaskLTE(int a, int b)
{
    return (((word32)b - a    ) >> 31) - 1;
}

/* Constant time - mask set when a != b. */
WC_INLINE byte ctMaskNotEq(int a, int b)
{
    return 0 - (a != b);
}