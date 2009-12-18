/* digest_sha1.h for QLDAP modified to use djb stuff */

/*        */
/*  SHA1  */
/*        */

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SHA1_H
#define _SHA1_H

#include "uint32.h"

typedef struct {
    uint32 state[5];
    uint32 count[2];  
    unsigned char buffer[64];
} SHA1_CTX;
 
#define SHA1_LEN 20

void SHA1Init(SHA1_CTX *);
void SHA1Update(SHA1_CTX *, const unsigned char *, size_t);
void SHA1Final(unsigned char [SHA1_LEN], SHA1_CTX *);

#endif /* _SHA1_H */
