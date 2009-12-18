/*
 * Copyright (c) 2003-2004 Claudio Jeker,
 *      Internet Business Solutions AG, CH-8005 Zürich, Switzerland
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Internet Business
 *      Solutions AG and its contributors.
 * 4. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#ifdef linux
#define _XOPEN_SOURCE
#endif
#include <unistd.h>
#include "base64.h"
#include "byte.h"
#include "case.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "str.h"
#include "stralloc.h"

#include "passwd.h"

static stralloc hashed = {0};
static stralloc salt = {0};
static stralloc intermediate = {0};
static stralloc cryptformat = {0};

static int do_crypt(char *, char *);
static int do_md4(char *, char *);
static int do_md5(char *, char *);
static int do_nsmta_md5(char *, char *);
static int do_smd5(char *, char *);
static int do_sha1(char *, char *);
static int do_ssha1(char *, char *);
static int do_rmd160(char *, char *);

static struct func {
	const char	*scheme;
	unsigned int	slen;
	int		(*func)(char *, char *);
} algo[] = {
	{ "{crypt}",	7, do_crypt },
	{ "{md4}",	5, do_md4 },
	{ "{md5}",	5, do_md5 },
	{ "{ns-mta-md5}", 12, do_nsmta_md5 },
	{ "{smd5}",	6, do_smd5 },
	{ "{sha}",	5, do_sha1 },
	{ "{ssha}",	6, do_ssha1 },
	{ "{rmd160}",	8, do_rmd160 },
	{ 0,		0, 0 }
};

/* return zero on success else the error number */
int
cmp_passwd(char *clear, char *encrypted)
{
	int	i, r;

	for (i = 0; algo[i].scheme != 0; i++) {
		if (case_diffb(encrypted, algo[i].slen, algo[i].scheme) == 0) {
			encrypted += algo[i].slen;
			r = algo[i].func(clear, encrypted);
			if (r != OK) return r;
			logit(256, "cpm_passwd: comparing hashed %s"
			    "passwd (%S == %s)\n", 
			    algo[i].scheme, hashed, encrypted);
			if (str_diffn(hashed.s, encrypted, hashed.len) == 0 &&
			    encrypted[hashed.len] == 0)
				return OK;
			/* hashed passwds are equal */
			return BADPASS;
		}
	}
	logit(256, "cpm_passwd: comparing crypt(3) passwd (%s == %s)\n", 
	    crypt(clear,encrypted), encrypted);
	if (str_diff(encrypted, crypt(clear,encrypted)) == 0)
		return OK;
#ifdef CLEARTEXTPASSWD
#warning ___CLEARTEXT_PASSWORD_SUPPORT_IS_ON___
	/* CLEARTEXTPASSWD ARE NOT GOOD */
	/* so they are disabled by default */
	if (str_diff(encrypted, clear) == 0)
		return OK;
#endif
	return BADPASS;
}

int
make_passwd(const char *want, char *clear, stralloc *result)
{
	int	i, r;

	for (i = 0; algo[i].scheme != 0; i++) {
		if (case_diffb(want, algo[i].slen, algo[i].scheme) == 0) {
			r = algo[i].func(clear, (char *) 0);
			if (r != OK) return r;
			if (!stralloc_copy(result, &hashed)) return ERRNO;
			return OK;
		}
	}
	return NOSUCH;
}

int
feed_salt(char *b, int l)
{
	if (!stralloc_copyb(&salt, b, l)) return ERRNO;
	return OK;
}

void
feed_crypt(const char *format)
{
	unsigned int len, slen;
	
	len = str_chr(format, 'X');
	if (format[len] != 'X') goto fail;
	if (!stralloc_copyb(&cryptformat, format, len)) goto fail;
	for (slen = len; format[slen] == 'X'; slen++) ;
	slen -= len;
	if (slen * 3 > salt.len * 4) goto fail; /* slen is in base64 but salt
						   is not. The conversion isn't
						   100% correct but close
						   enough. */
	if (b64_ntops(salt.s, slen, &intermediate) == -1) goto fail;
	if (!stralloc_catb(&cryptformat, intermediate.s, slen)) goto fail;
	if (!stralloc_0(&cryptformat)) goto fail;
	return;
	
fail:
       	/* crypt will fail later */
	if (!stralloc_copys(&cryptformat, "")) return;
	if (!stralloc_copys(&intermediate, "")) return;
}

static int
do_crypt(char *clear, char *encrypted)
{
	if (encrypted) {
		if (!stralloc_copys(&hashed, crypt(clear, encrypted)))
			return ERRNO;
	} else {
		/* salt and prefix */
		if (cryptformat.s == 0 || cryptformat.len == 0)
			return ILLVAL;
		if (!stralloc_copys(&hashed, crypt(clear, cryptformat.s)))
			return ERRNO;
	}
	return OK;
}

static int
do_md4(char *clear, char *encrypted)
{
	MD4_CTX ctx;
	unsigned char buffer[MD4_LEN];

	/* not slated */
	MD4Init(&ctx);
	MD4Update(&ctx, clear, str_len(clear));
	MD4Final(buffer,&ctx);
	if (b64_ntops(buffer, sizeof(buffer), &hashed) == -1) return ERRNO;

	return OK;
}

static int
do_md5(char *clear, char *encrypted)
{
	MD5_CTX ctx;
	unsigned char buffer[MD5_LEN];

	MD5Init(&ctx);
	MD5Update(&ctx, clear, str_len(clear));
	MD5Final(buffer,&ctx);
	if (b64_ntops(buffer, sizeof(buffer), &hashed) == -1) return ERRNO;

	return OK;
}

static int
do_nsmta_md5(char *clear, char *encrypted)
{
/*
 * Netscape MTA MD5 as found in Netscape MailServer < 2.02 and 
 * Software.com's Post.Office
 */
	MD5_CTX ctx;
	unsigned char buffer[MD5_LEN];
	unsigned char c;

	/* NS-MTA-MD5 */
	if (encrypted) {
		if (str_len(encrypted) != 64)
			return BADVAL;
	
		MD5Init(&ctx);
		MD5Update(&ctx, &encrypted[32], 32);
		c = 89;
		MD5Update(&ctx, &c, 1);
		MD5Update(&ctx, clear, str_len(clear));
		c = 247;
		MD5Update(&ctx, &c, 1);
		MD5Update(&ctx, &encrypted[32], 32);
		MD5Final(buffer, &ctx);

		if (hex_ntops(buffer, sizeof(buffer), &hashed) == -1)
			return ERRNO;
		if (!stralloc_catb(&hashed, &encrypted[32], 32)) return ERRNO;
		
		return OK;
	} else {
		if (salt.s == 0 || salt.len < 16)
			return FAILED;
		if (hex_ntops(salt.s, 16, &intermediate) == -1) return ERRNO;
		if (intermediate.len != 32) return FAILED;
		
		MD5Init(&ctx);
		MD5Update(&ctx, intermediate.s, 32);
		c = 89;
		MD5Update(&ctx, &c, 1);
		MD5Update(&ctx, clear, str_len(clear));
		c = 247;
		MD5Update(&ctx, &c, 1);
		MD5Update(&ctx, intermediate.s, 32);
		MD5Final(buffer, &ctx);

		if (hex_ntops(buffer, sizeof(buffer), &hashed) == -1)
			return ERRNO;
		if (!stralloc_cat(&hashed, &intermediate)) return ERRNO;
		
		return OK;
	}
}

static int
do_smd5(char *clear, char *encrypted)
{
	MD5_CTX ctx;
	
	if (encrypted) {
		if (b64_ptons(encrypted, &salt) == -1)
			return BADVAL;

		MD5Init(&ctx);
		MD5Update(&ctx, clear, str_len(clear));
		MD5Update(&ctx, salt.s + MD5_LEN, salt.len - MD5_LEN);
		MD5Final(salt.s,&ctx);
		if (b64_ntops(salt.s, salt.len, &hashed) == -1)
			return ERRNO;
		return OK;
	} else {
		if (salt.s == 0 || salt.len < 4)
			return FAILED;
		if (!stralloc_ready(&intermediate, MD5_LEN)) return ERRNO;
		intermediate.len = MD5_LEN;
		MD5Init(&ctx);
		MD5Update(&ctx, clear, str_len(clear));
		MD5Update(&ctx, salt.s, salt.len);
		MD5Final(intermediate.s,&ctx);
		
		if (!stralloc_cat(&intermediate, &salt)) return ERRNO;
		if (b64_ntops(intermediate.s, intermediate.len, &hashed) == -1)
			return ERRNO;
		
		return OK;
	}
}

static int
do_sha1(char *clear, char *encrypted)
{
	SHA1_CTX ctx;
	unsigned char buffer[SHA1_LEN];

	SHA1Init(&ctx);
	SHA1Update(&ctx, clear, str_len(clear));
	SHA1Final(buffer,&ctx);
	if (b64_ntops(buffer, sizeof(buffer), &hashed) == -1) return ERRNO;

	return OK;
}

static int
do_ssha1(char *clear, char *encrypted)
{
	SHA1_CTX ctx;
	
	if (encrypted) {
		if (b64_ptons(encrypted, &salt) == -1)
			return BADVAL;

		SHA1Init(&ctx);
		SHA1Update(&ctx, clear, str_len(clear));
		SHA1Update(&ctx, salt.s + SHA1_LEN, salt.len - SHA1_LEN);
		SHA1Final(salt.s,&ctx);
		if (b64_ntops(salt.s, salt.len, &hashed) == -1)
			return ERRNO;
		return OK;
	} else {
		if (salt.s == 0 || salt.len < 4)
			return FAILED;
		if (!stralloc_ready(&intermediate, SHA1_LEN)) return ERRNO;
		intermediate.len = SHA1_LEN;
		SHA1Init(&ctx);
		SHA1Update(&ctx, clear, str_len(clear));
		SHA1Update(&ctx, salt.s, salt.len);
		SHA1Final(intermediate.s,&ctx);
		
		if (!stralloc_cat(&intermediate, &salt)) return ERRNO;
		if (b64_ntops(intermediate.s, intermediate.len, &hashed) == -1)
			return ERRNO;
		
		return OK;
	}
}

static int
do_rmd160(char *clear, char *encrypted)
{
	RMD160_CTX ctx;
	unsigned char buffer[RMD160_LEN];

	RMD160Init(&ctx);
	RMD160Update(&ctx, clear, str_len(clear));
	RMD160Final(buffer,&ctx);
	if (b64_ntops(buffer, sizeof(buffer), &hashed) == -1) return ERRNO;

	return OK;
}

