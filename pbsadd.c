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
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "ip.h"
#include "open.h"
#include "readwrite.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"

static void die(void);
static void logit(const char* );
static void logits(const char *);
static void die_badenv(void);
static void die_control(void);
static void die_dir(void);
static void die_exec(void);
static void die_secret(void);
static void log_socket(void);
static void die_dirback(void);
static void die_envs(void);
static void log_nomem(void);
static void log_envsize(void);
static void log_envvar(char *);

void setup(void);
static void uint16_pack_big(char [], unsigned int);
int sendrequest(int, char *, unsigned int, struct ip_address *);
unsigned int addenv(char *, unsigned int);

char sserrbuf[128];
substdio sserr = SUBSTDIO_FDBUF(subwrite,2,sserrbuf,sizeof sserrbuf);

char **childargs;

#define MAX_PACKET_SIZE 1024
char packet[MAX_PACKET_SIZE];

stralloc addresses = {0};
stralloc envs = {0};
stralloc secret = {0};
struct ip_address *servers;
unsigned int numservers = 0;
unsigned int numenvs = 0;
unsigned int serverport = 2821;

void
setup(void)
{
	char* s;
	unsigned int i, len;
	int fdsourcedir;

	fdsourcedir = open_read(".");
	if (fdsourcedir == -1)
		die_dir();

	if (chdir(auto_qmail) == -1) die_control();

	if (control_readfile(&addresses,"control/pbsservers",0) != 1)
		die_control();

	if (control_readint(&serverport,"control/pbsport") == -1)
		die_control();
	if (serverport > 65000)
		die_control();
	if (control_rldef(&secret,"control/pbssecret",0,"") != 1)
		die_control();
	if (secret.len > 255)
		die_secret();
	if (control_readfile(&envs,"control/pbsenv",0) == -1)
		die_control();

	if (fchdir(fdsourcedir) == -1)
		die_dirback();
	close(fdsourcedir);

	for (i = 0; i < addresses.len; i++)
		if(addresses.s[i] == '\0') numservers++;
	if (numservers == 0) die_control();

	for (i = 0; i < envs.len; i++)
		if(envs.s[i] == '\0') numenvs++;
	if (numenvs > 255) die_envs();

	servers = (struct ip_address*)
	    alloc(numservers * sizeof(struct ip_address));
	if (!servers) log_nomem();

	s = addresses.s;
	for (i = 0; i < numservers; i++) {
		len = ip_scan(s, &servers[i]);
		if (len == 0 || len > 15) die_control();
		while (*s++);
	}

}


static void
uint16_pack_big(char s[2], unsigned int u)
{
	s[1] = u & 255;
	s[0] = (u >> 8) & 255;
}

int
sendrequest(int fd, char *buf, unsigned int len, struct ip_address *ip)
{
	struct sockaddr_in s;

	byte_zero(&s,sizeof(s));
	byte_copy(&s.sin_addr,4,ip);
	uint16_pack_big((char *)&s.sin_port, serverport);
	s.sin_family = AF_INET;

	return sendto(fd, buf, len, 0, (struct sockaddr*)&s, sizeof(s));
}


unsigned int
addenv(char *buf, unsigned int len)
{
	unsigned int i;
	unsigned int vlen;	/* length of the envvar  */
	unsigned int elen;	/* length of the envname */
	unsigned int telen;	/* length of the envline envname=rewritename */
	unsigned int olen;	/* old length of the packet buffer */
	char *e;
	char *v;

	olen = len;
	buf += len;
	*buf++ = numenvs; len++;

	e = envs.s;
	for (i=0; i < numenvs; i++) {
		telen = str_len(e);
		/* we are not interested in the rewrite name */
		elen = str_chr(e, '=');
		e[elen] = '\0';

		/* get the requested envvar */
		v = env_get(e);
		vlen = v != (char *)0?str_len(v):0;

		/* write the result */
		if (elen + vlen + 1 > 255) {
			/* Check that length indicator does not overflow */
			log_envvar(e);
			return olen;
		}
		if (len + elen + vlen + 2 > MAX_PACKET_SIZE) {
			/*
			 * Packet may not overflow.
			 * The environment is written like this:
			 *   [length]envname"="envvar
			 */
			log_envsize();
			return olen;
		}
		*buf++ = elen + vlen + 1; len++; /* length */
		byte_copy(buf, elen, e); buf+=elen, len+=elen; /* envname */
		*buf++ = '='; len++; /* "=" */
		if (vlen != 0) {
			byte_copy(buf, vlen, v);
			buf+=vlen;
			len+=vlen;
		}
		if (len > MAX_PACKET_SIZE) {
			/* call me paranoid ... */
			log_envsize();
			return olen;
		}
		e += telen + 1;
	}
	return len;
}

int
main(int argc, char** argv)
{
	struct ip_address ip;
	char *ipstr;
	char *s;
	int sfd;
	unsigned int i, len;

	childargs = argv + 1;

	if (env_get("NOPBS")) goto done;

	setup();

	ipstr = env_get("TCPREMOTEIP");
	if (!ipstr) die_badenv();
	len = ip_scan(ipstr, &ip);
	if (len == 0 || len > 15) die_badenv();

	sfd = socket(AF_INET,SOCK_DGRAM,0);
	if (sfd == -1) {
		log_socket();
		goto done;
	}

	/* create request */
	s = packet; len = 0;
	*s++ = 'A'; len++; /* ADD */
	*s++ = 4; len++;   /* Size of address in bytes (4 IPv4|16 IPv6) */
	byte_copy(s, 4, &ip); s+=4; len+=4;
	*s++ = secret.len; len++;   /* secret length */
	byte_copy(s, secret.len, secret.s); s+=secret.len; len+=secret.len;
	len = addenv(packet, len);

	/* send update notification to all servers */
	for (i = 0; i < numservers; i++) {
		sendrequest(sfd, packet, len, &servers[i]);
	}
	close(sfd); /* try to close socket */
done:
	if (!*childargs) _exit(0);
	else execvp(*childargs,childargs);
	/* should never reach this point */
	die_exec();
	/* NOTREACHED */
	return 1;
}

static void
die(void)
{
	_exit(1);
}

static void
logit(const char* s)
{
	substdio_puts(&sserr,s);
	substdio_puts(&sserr,"\n");
	substdio_flush(&sserr);  
}

static void
logits(const char *s)
{
	substdio_puts(&sserr,s);
}

static void
die_badenv(void)
{
	logit("pbsadd unable to read $TCPREMOTEIP"); die();
}

static void
die_control(void)
{
	logit("pbsadd unable to read controls"); die();
}

static void
die_dir(void)
{
	logit("pbsadd unable to open current directory"); die();
}

static void
die_exec(void)
{
	logit("pbsadd unable to start pop3 daemon"); die();
}

static void
die_secret(void)
{
	logit("pbsadd control/pbssecret is to long"); die();
}

static void
log_socket(void)
{
	logit("pbsadd socket syscall failed");
}

static void
die_dirback(void)
{
	logit("pbsadd unable to switch back to source directory");
	die();
}

static void
die_envs(void)
{
	logit("pbsadd control/pbsenvs has to many entries");
	die();
}

static void
log_nomem(void)
{
	logit("pbsadd out of memory"); 
	if (*childargs) _exit(111);
	else execvp(*childargs,childargs);
	/* should never reach this point */
	die_exec();
}

static void
log_envsize(void)
{
	logit("pbsadd to many environment entries (pkg to small)");
}

static void
log_envvar(char *s)
{
	logits("pbsadd environment "); logits(s); logit(" is to big"); 
}

