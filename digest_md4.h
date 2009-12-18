/* digest_md4.h for QLDAP modified to use djb's stuff */

/*        */
/*  MD4   */
/*        */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.
   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.                                   */

#ifndef _MD4_H_
#define _MD4_H_

#include "uint32.h"

/* MD4 context. */
typedef struct MD4Context {
    uint32 state[4];            /* state (ABCD) */
    uint32 count[2];            /* number of bits, modulo 2^64 */
    unsigned char buffer[64];   /* input buffer */
} MD4_CTX;

#define MD4_LEN 16

void   MD4Init(MD4_CTX *);
void   MD4Update(MD4_CTX *, const unsigned char *, size_t);
void   MD4Final(unsigned char [MD4_LEN], MD4_CTX *);

#endif /* _MD4_H_ */
