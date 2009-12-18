/*
 * Copyright (c) 2002-2004 Claudio Jeker,
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "alloc.h"
#include "auto_qmail.h"
#include "byte.h"
#include "control.h"
#include "ip.h"
#include "ndelay.h"
#include "now.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"
#include "uint32.h"

static void die_control(void);
static void die_nomem(void);
static void init(void);
static int socket_bind(int);
static void cache_impossible(void);
static void set4(unsigned long, uint32);
static uint32 get4(unsigned long);
unsigned long hash(const unsigned char *,unsigned int);
void unlinkaddr(const unsigned char *, unsigned int);
void setaddr(const unsigned char *, unsigned int,
    unsigned long, char *, unsigned int);
int checkaddr(const unsigned char *, unsigned int,
    unsigned long, char **, unsigned int *);
static int doit(void);

struct ip_address ip;
unsigned int port = 2821;
stralloc addr = {0};
stralloc secret = {0};
unsigned int timeout = 600; /* 10 Min */

unsigned long cachesize = 1048576; /* 1 MB */
unsigned char *cache;
unsigned long hashsize;
unsigned int hashbits;
unsigned long writer;
unsigned long oldest;
unsigned long unused;

static unsigned char buf[1024];
static unsigned int len;

#define fatal "pbsdbd: fatal: "
#define warning "pbsdbd: warning: "
#define info "pbsdbd: info: "

static void
die_control(void)
{
       	strerr_die2x(111, fatal, "unable to read controls");
}

static void
die_nomem(void)
{
       	strerr_die2x(111, fatal, "out of memory");
}

static void
init(void)
{
	unsigned int l;

	if (chdir(auto_qmail) == -1) die_control();

	if (control_rldef(&addr,"control/pbsip",0, "0.0.0.0") == -1)
		die_control();
	if (!stralloc_0(&addr)) die_nomem();

	l = ip_scan(addr.s, &ip);
	if (l == 0 && l > 15) die_control();

	if (control_rldef(&secret,"control/pbssecret",0,"") != 1)
		die_control();

	if (control_readint(&port,"control/pbsport") == -1) die_control();
	if (port > 65000) die_control();

	/* if a luser sets bad values it's his fault */
	if (control_readulong(&cachesize,"control/pbscachesize") == -1)
		die_control();
	if (control_readint(&timeout,"control/pbstimeout") == -1)
		die_control();

	cache = alloc(cachesize);
	if (!cache) die_nomem();

	hashsize = 4;
	while (hashsize <= (cachesize >> 5)) hashsize <<= 1;

	writer = hashsize;
	oldest = cachesize;
	unused = cachesize;

}

static int
socket_bind(int s)
{
	int opt = 1;
	struct sockaddr_in soin;
	char *x;

	setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);

	byte_zero(&soin,sizeof(soin));
	byte_copy(&soin.sin_addr,4,&ip);
	x = (char *) &soin.sin_port;
	x[1] = port; port >>= 8; x[0] = port;
	soin.sin_family = AF_INET;

	return bind(s,(struct sockaddr *) &soin,sizeof soin);
}

static void
cache_impossible(void)
{
	strerr_die2x(111, fatal, "cache corrupted");
}

static void
set4(unsigned long pos, uint32 u)
{
	unsigned char *s;

	if (pos > cachesize - 4) cache_impossible();

	s = cache + pos;
	s[3] = u & 255;
	u >>= 8;
	s[2] = u & 255;
	u >>= 8;
	s[1] = u & 255;
	s[0] = u >> 8;  
}

static uint32
get4(unsigned long pos)
{
	unsigned char *s;
	uint32 result;  

	if (pos > cachesize - 4) cache_impossible();
	s = cache + pos;
	result = s[0];
	result <<= 8;
	result += s[1];
	result <<= 8;
	result += s[2];
	result <<= 8;
	result += s[3];

	return result;
}

unsigned long
hash(const unsigned char *key,unsigned int keylen)
{
	unsigned long result = 5381;

	while (keylen) {
		result = (result << 5) + result;
		result ^= *key;
		++key;
		--keylen;
	}
	result <<= 2;
	result &= hashsize - 4;
	return result;
}

void
unlinkaddr(const unsigned char *key, unsigned int keylen)
{
	unsigned long pos;
	unsigned long prevpos;
	unsigned long nextpos;
	unsigned int loop;

	if (!cache) return;

	prevpos = hash(key,keylen);
	pos = get4(prevpos);
	loop = 0;

	while (pos) {
		if (pos + 13 > cachesize) cache_impossible();
		nextpos = prevpos ^ get4(pos);
		if (nextpos == prevpos) cache_impossible();
		if (*(cache + pos + 12) == keylen) {
			if (pos + 13 + keylen > cachesize) cache_impossible();
			if (byte_equal(key,keylen,cache + pos + 13)) {
				set4(prevpos, get4(prevpos) ^ pos ^ nextpos);
				if (nextpos != 0)
					set4(nextpos,
					    get4(nextpos) ^ pos ^ prevpos);
				set4(pos, 0);
				//strerr_warn2(info, "clearing entry.", 0);
				return;
			}
		}
		prevpos = pos;
		pos = nextpos;
		if (++loop > 100) {
			strerr_warn2(warning, "hash flooding", 0);
			return; /* to protect against hash flooding */
		}
	}
}

/* to be stored: 4-byte link, 4-byte timestamp, 4-byte envsize, 1-byte size,
   size-byte Address and envsize-byte Environment */
/* see also dnscache */
void
setaddr(const unsigned char *key, unsigned int keylen,
    unsigned long timenow, char *env, unsigned int envlen)
{
	unsigned int entrylen;
	unsigned int tmplen;
	unsigned int keyhash;
	unsigned long pos;

	if (!cache) return;
	if (keylen > 255) return;

	entrylen = 13 + keylen + envlen;

	unlinkaddr(key, keylen);

	while (writer + entrylen > oldest) {
		if (oldest == unused) {
			if (writer <= hashsize) cache_impossible();
			unused = writer;
			oldest = hashsize;
			writer = hashsize;
			strerr_warn2(info, "reached end of cache, wrapping...", 0);
		}

		pos = get4(oldest);
		if (!pos)
			strerr_warn2(info, "skipping cleared entry", 0);
		if (pos)
			set4(pos,get4(pos) ^ oldest);

		if (oldest + 13 > cachesize) cache_impossible();
		tmplen = get4(oldest + 8);
		oldest += 13 + tmplen + *(cache + oldest + 12);
		if (oldest > unused) cache_impossible();
		if (oldest == unused) {
			unused = cachesize;
			oldest = cachesize;
		}
	}

	keyhash = hash(key,keylen);

	pos = get4(keyhash);
	if (pos)
		set4(pos,get4(pos) ^ keyhash ^ writer);
	set4(writer,pos ^ keyhash);
	set4(writer + 4,timenow + timeout);
	set4(writer + 8,envlen);
	if (writer + 13 > cachesize) cache_impossible();
	*(cache + writer + 12) = keylen;
	byte_copy(cache + writer + 13,keylen,key);
	byte_copy(cache + writer + 13 + keylen,envlen,env);

	set4(keyhash,writer);

	writer += entrylen;
}

int
checkaddr(const unsigned char *key, unsigned int keylen,
    unsigned long timenow, char **env, unsigned int *envlen)
{
	unsigned long pos;
	unsigned long prevpos;
	unsigned long nextpos;
	unsigned long u;
	unsigned int loop;

	if (!cache) return 0;

	prevpos = hash(key,keylen);
	pos = get4(prevpos);
	loop = 0;
	*env = 0;
	*envlen = 0;

	while (pos) {
		if (pos + 13 > cachesize) cache_impossible();
		if (*(cache + pos + 12) == keylen) {
			if (pos + 13 + keylen > cachesize) cache_impossible();
			if (byte_equal(key,keylen,cache + pos + 13)) {
				u = get4(pos + 4);
				if (u < timenow) {
					//strerr_warn2(info,
					//    "cache hit but timed out", 0);
					return 0;
				}
				*envlen = get4(pos + 8);
				if (pos + 13 + keylen + *envlen > cachesize)
					cache_impossible();
				*env = cache + pos + 13 + keylen;
				return 1;
			}
		}
		nextpos = prevpos ^ get4(pos);
		if (nextpos == prevpos) cache_impossible();
		prevpos = pos;
		pos = nextpos;
		if (++loop > 100) {
			strerr_warn2(warning, "hash flooding", 0);
			return 0; /* to protect against hash flooding */
		}
	}

	//strerr_warn2(info, "not in cache", 0);
	return 0;
}


/*
 * pbs packets have following format:
 *   header:
 *   1-byte type, 1-byte address-size, address-size-byte
 *
 *   secret used in type add packets:
 *   1-byte secret-size, secret-size-bytes secret
 *
 *   may-relay byte used in respnse packets:
 *   1-byte may-relay ('R' for may-relay and 'N' for may-not-relay)
 *
 *   optional environment vars for type add and result:
 *   1-byte #-of-entries
 *   environment vars entries
 *   1-byte size, n-byte env-name, 1-byte '"', m-byte env-var
 *   where n + m + 1 = size.
 *
 *   Allowed types are 'A' for add, 'Q' for query, 'R' response.
 *   Type 'A' uses the header and secret plus optional environment vars.
 *   Type 'Q' does only need the header.
 *   Type 'R' needs the header and the may-relay byte and
 *   optional environment vars.
 */

static int doit(void)
{
	unsigned char *sec;
	unsigned int sec_len;
	unsigned char *env;
	unsigned long timenow;
	unsigned int envlen;
	unsigned int i;

	if ((unsigned int)buf[1] + 2 >= len) {
		strerr_warn2(warning, "bad packet", 0);
		return 0;
	}

	timenow = now();

	switch (buf[0]) {
	case 'Q':
		//strerr_warn2(info, "query packet", 0);
		if (checkaddr(&buf[2], buf[1], timenow,
			    (char**)&env, &envlen)) {
			*(buf + 2 + buf[1]) = 'R';
			if (envlen + buf[1] + 3 > 1024) {
				strerr_warn2(warning, "environment would "
				    "exceed package size, dropped", 0);
				return 0;
			}
			byte_copy(buf+3+buf[1], envlen, env);
			len += envlen;
		} else {
			*(buf + 2 + buf[1]) = 'N';
		}
		buf[0] = 'R';
		return 1;
	case 'A':
		//strerr_warn2(info, "add packet", 0);
		sec_len = *(buf + 2 + buf[1]);
		sec = buf + 2 + buf[1] + 1;
		if (buf + len < sec + sec_len) {
			strerr_warn2(warning, "bad packet", 0);
			return 0;
		}
		if (secret.len != sec_len ||
		    byte_diff(secret.s, sec_len, sec)) {
			strerr_warn2(warning, "no authorized add packet", 0);
			return 0;
		}
		env = buf + 3 + buf[1] + *(buf + 2 + buf[1]);
		envlen = 1;
		for (i=0; i < *env; i++) {
			envlen += env[envlen] + 1;
			if (buf + len < env + envlen) {
				strerr_warn2(warning, "environment would "
				    "exceed package size, dropped", 0);
				return 0;
			}
		}
		if (buf + len != env + envlen) {
			strerr_warn2(warning, "trailing garbadge at end "
			    "of packet, dropped", 0);
			return 0;
		}
		setaddr(&buf[2], buf[1], timenow, env, envlen);
		return 0;
	case 'R':
		strerr_warn2(warning, "response recived", 0);
		return 0;
	default:
		strerr_warn2(warning, "bad packet", 0);
		return 0;
	}
}

int main(int argc, char** argv)
{
	struct sockaddr_in sa;
	unsigned int dummy;
	int udp;

	init();

	udp = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp == -1)
		strerr_die2sys(111,fatal,"unable to create UDP socket: ");
	if (socket_bind(udp) == -1)
		strerr_die2sys(111,fatal,"unable to bind UDP socket: ");

	ndelay_off(udp);

	for (;;) {
		dummy = sizeof(sa);
		len = recvfrom(udp, buf, sizeof(buf), 0,
		    (struct sockaddr*) &sa, &dummy);
		if (len < 0) continue;
		if (!doit()) continue;
		sendto(udp, buf, len, 0, (struct sockaddr*) &sa, sizeof(sa));
		/* may block for buffer space; if it fails, too bad */
	}
}

