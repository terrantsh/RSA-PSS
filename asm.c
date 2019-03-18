/* asm.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "types.h"

/* ISO C code */
#define MONT_START
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL                                      \
   do { fp_word t;                                    \
   t  = ((fp_word)_c[0] + (fp_word)cy) +              \
                (((fp_word)mu) * ((fp_word)*tmpm++)); \
   _c[0] = (fp_digit)t;                               \
   cy = (fp_digit)(t >> DIGIT_BIT);                   \
   } while (0)

#define PROPCARRY \
   do { fp_digit t = _c[0] += cy; cy = (t < cy); } while (0)


/******************************************************************/


#define LO  0
/* end fp_montogomery_reduce.c asm */



/* ISO C portable code */

#define COMBA_START

#define CLEAR_CARRY \
   c0 = c1 = c2 = 0;

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define CARRY_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);



/* multiplies point i and j, updates carry "c1" and digit c2 */
#define SQRADD(i, j)                                 \
   do { fp_word t;                                   \
   t = c0 + ((fp_word)i) * ((fp_word)j);  c0 = (fp_digit)t;    \
   t = c1 + (t >> DIGIT_BIT);             c1 = (fp_digit)t;    \
                                          c2 +=(fp_digit) (t >> DIGIT_BIT); \
   } while (0);


/* for squaring some of the terms are doubled... */
#define SQRADD2(i, j)                                                 \
   do { fp_word t,tt;                                                    \
   t  = ((fp_word)i) * ((fp_word)j);                                  \
   tt = (fp_word)c0 + t;                 c0 = (fp_digit)tt;           \
   tt = (fp_word)c1 + (tt >> DIGIT_BIT); c1 = (fp_digit)tt;           \
                                         c2 +=(fp_digit)(tt >> DIGIT_BIT);     \
   tt = (fp_word)c0 + t;                 c0 = (fp_digit)tt;                    \
   tt = (fp_word)c1 + (tt >> DIGIT_BIT); c1 = (fp_digit)tt;            \
                                         c2 +=(fp_digit)(tt >> DIGIT_BIT);     \
   } while (0);

#define SQRADDSC(i, j)                                                         \
   do { fp_word t;                                                             \
      t =  ((fp_word)i) * ((fp_word)j);                                        \
      sc0 = (fp_digit)t; sc1 = (t >> DIGIT_BIT); sc2 = 0;                      \
   } while (0);

#define SQRADDAC(i, j)                                                         \
   do { fp_word t;                                                             \
   t = sc0 + ((fp_word)i) * ((fp_word)j);  sc0 =  (fp_digit)t;                 \
   t = sc1 + (t >> DIGIT_BIT);             sc1 =  (fp_digit)t;                 \
                                           sc2 += (fp_digit)(t >> DIGIT_BIT);  \
   } while (0);

#define SQRADDDB                                                               \
   do { fp_word t;                                                             \
   t = ((fp_word)sc0) + ((fp_word)sc0) + c0; c0 = (fp_digit)t;                 \
   t = ((fp_word)sc1) + ((fp_word)sc1) + c1 + (t >> DIGIT_BIT);                \
                                             c1 = (fp_digit)t;                 \
   c2 = c2 + (fp_digit)(((fp_word)sc2) + ((fp_word)sc2) + (t >> DIGIT_BIT));   \
   } while (0);



/* start fp_mul_comba.c asm */
/* these are the combas.  Worship them. */



/* ISO C code */

#define COMBA_START

#define COMBA_CLEAR \
   c0 = c1 = c2 = 0;

#define COMBA_FORWARD \
   do { c0 = c1; c1 = c2; c2 = 0; } while (0);

#define COMBA_STORE(x) \
   x = c0;

#define COMBA_STORE2(x) \
   x = c1;

#define COMBA_FINI

#define MULADD(i, j)                                                                                                                                  \
   do { fp_word t;                                      \
   t = (fp_word)c0 + ((fp_word)i) * ((fp_word)j);       \
   c0 = (fp_digit)t;                                    \
   t = (fp_word)c1 + (t >> DIGIT_BIT);                  \
   c1 = (fp_digit)t;                                    \
   c2 += (fp_digit)(t >> DIGIT_BIT);                    \
   } while (0);



/* end fp_mul_comba.c asm */

