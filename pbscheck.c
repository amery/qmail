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
#include "now.h"
#include "open.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

static void die(void);
static int safewrite(int, void *, int);
static void putstr(const char *);
static void flush(void);
static void errstr(const char *);
static void logit(const char *);
static void die_usage(void);
static void die_exec(void);
static void die_badenv(void);
static void die_control(void);
static void die_nomem(void);
static void die_envs(void);
static void die_dir(void);
static void die_dirback(void);
void setup(void);
static void uint16_pack_big(char [], unsigned int);
int sendrequest(int, char *, unsigned int, struct ip_address *);
int env_snap(void);
void env_rewrite(char**, char**);
void setenv(char *, unsigned int);

char ssoutbuf[128];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

char sserrbuf[128];
substdio sserr = SUBSTDIO_FDBUF(safewrite,2,sserrbuf,sizeof sserrbuf);

#define MAX_PACKET_SIZE 1024
char packet[MAX_PACKET_SIZE];

stralloc addresses = {0};
stralloc envs = {0};
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
	if (control_readfile(&envs,"control/pbsenv",0) == -1)
	       	die_control();

	if (fchdir(fdsourcedir) == -1)
		die_dirback();
	close(fdsourcedir);

	for (i = 0; i < addresses.len; i++)
		if( addresses.s[i] == '\0') numservers++;
	if (numservers == 0) die_control();

	for (i = 0; i < envs.len; i++)
		if( envs.s[i] == '\0') numenvs++;
	if (numenvs > 255) die_envs();

	servers = (struct ip_address*)
	    alloc(numservers * sizeof(struct ip_address));
	if (!servers) die_nomem();

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

char **envsnap;

int
env_snap(void)
{
	unsigned int en, i;
	
	for (en = 0;environ[en];++en) ;
	envsnap = (char **) alloc((en + 1) * sizeof(char *));
	if (!envsnap) return 0;
	for (en = 0;environ[en];++en) {
		envsnap[en] = alloc(str_len(environ[en]) + 1);
		if (!envsnap[en]) {
			for (i = 0; i < en; ++i) alloc_free(envsnap[i]);
			alloc_free(envsnap);
			return 0;
		}
		str_copy(envsnap[en],environ[en]);
	}
	envsnap[en] = 0;
	return 1;
}

stralloc vbuf = {0};

void
env_rewrite(char** name, char** value)
{
	char *e;
	unsigned int i;
	unsigned int llen;
	unsigned int nlen;
	unsigned int elen;

	e = envs.s;
	nlen = str_len(*name);

	for (i=0; i < numenvs; i++) {
		llen = str_len(e);
		if (byte_equal(*name, nlen, e))
			if (*(e + nlen) == '=') {
				elen = str_chr(e + nlen + 1, '=');
				if (*(e + nlen + elen + 1) == '=') {
					*(e + nlen + elen + 1) = '\0';
					if (!stralloc_copys(&vbuf,
						    e + nlen + elen + 2))
						die_nomem();
					if (!stralloc_cats(&vbuf, *value))
						die_nomem();
					if (!stralloc_0(&vbuf)) die_nomem();
					*value = vbuf.s;
				}
				*name = e + nlen + 1;
				return;
			}
		e += llen + 1;
	}
}

void setenv(char *env, unsigned int envlen)
{
	char *v;
	char *e;
	unsigned int numenv;
	unsigned int elen;
	unsigned int nlen;
	unsigned int tlen;
	unsigned int i;

	if (!env_snap()) die_nomem();

	numenv=(unsigned char)*env++; envlen--;

	nlen=(unsigned char)*env++; envlen--;
	for (i=0; i < numenv; i++) {
		elen=nlen;
		if (envlen <= 0) {
			environ = envsnap;
			return;
		}
		nlen=(unsigned char)*(env+elen);
		*(env+elen)=0;
		tlen = str_chr(env, '=');
		env[tlen] = '\0';
		e = env;
		v = env + tlen + 1;
		env_rewrite(&e, &v);
		if (!env_put2(e, v)) die_nomem();
		env+=elen+1; envlen-=(elen+1);
	}
}

int main (int argc, char** argv)
{
	struct ip_address ip;
	char **childargs;
	char *ipstr;
	char *s;
	unsigned long t;
	int sfd = -1;
	unsigned int len;
	int i;

	childargs = argv + 1;
	if (!*childargs) die_usage();

	if (env_get("NOPBS")) goto start_daemon;

	setup();

	t = now() ^ getpid(); /* at least on OpenBSD this is mostly random */
	t %= numservers;

	ipstr = env_get("TCPREMOTEIP");
	if (!ipstr) die_badenv();
	len = ip_scan(ipstr, &ip);
	if (len == 0 || len > 15) die_badenv();

	sfd = socket(AF_INET,SOCK_DGRAM,0);
	if (sfd == -1) goto start_daemon;

	/* create request */
	s = packet; len = 0;
	*s++ = 'Q'; len++; /* Query */
	*s++ = 4; len++;   /* Size of address in bytes (4 IPv4|16 IPv6) */
	byte_copy(s, 4, &ip); s+=4; len+=4;
	*s++ = 0; len++;   /* status */

	i = sendrequest(sfd, packet, len, &servers[t]);
	if (i <= 0) goto start_daemon;
	t = 0;
	do {
		/* wait a seconds for answer */
		i = timeoutread(1, sfd, packet, sizeof(packet));
		if (i != -1) break;
		if (i == -1 && errno != error_timeout) goto start_daemon;

		if (t >= numservers) {
			logit("pbscheck: no response from server");
			goto start_daemon; /* no response */
		}

		i = sendrequest(sfd, packet, len, &servers[t]);
		if (i <= 0) goto start_daemon;
		t++;

	} while(1);

	if (packet[0] != 'R') goto start_daemon; /* R = Reply */
	if (packet[1] != 4) goto start_daemon;
	/* check address */
	if (byte_diff(packet + 2, 4, &ip)) goto start_daemon;
	if (*(packet + 2 + packet[1]) == 'R') {
		if (!env_put("RELAYCLIENT=")) die_nomem();
	}
	setenv(packet + 3 + packet[1], i - packet[1] - 3);

start_daemon:
	if (sfd == -1) close(sfd); /* try to close socket */

	/* start smtpd */
	execvp(*childargs,childargs);
	/* should never reach this point */
	die_exec();
	/* NOTREACHED */
	return 1;
}

static void die(void)
{
	_exit(1);
}

static int safewrite(int fd, void *buf, int len)
{
	int r;
	r = timeoutwrite(1200,fd,buf,len);
	if (r <= 0) die();
	return r;
}

static void putstr(const char *s)
{
	substdio_puts(&ssout,s);
}

static void flush(void)
{
	substdio_flush(&ssout);
}

static void errstr(const char *s)
{
	putstr(s);
	putstr("\r\n");
	flush();
}

static void logit(const char *s)
{
	substdio_puts(&sserr,s);
	substdio_puts(&sserr,"\n");
	substdio_flush(&sserr);  
}

static void die_usage(void)
{
	errstr("554 pop before smtp subprogram uncorrectly installed (#5.3.5)");
	logit("usage: pbscheck subprogram ...");
	die();
}

static void die_exec(void)
{
	errstr("554 unable to start smtp daemon (#5.3.5)");
	logit("pbscheck: unable to start smtp daemon");
	die();
}

static void die_badenv(void)
{
	errstr("554 unable to read $TCPREMOTEIP (#5.3.5)");
	logit("pbscheck: unable to read $TCPREMOTEIP");
	die();
}

static void die_control(void)
{
	errstr("554 unable to read controls (#5.3.5)");
	logit("pbscheck unable to read controls");
	die();
}

static void die_nomem(void)
{
	errstr("421 out of memory (#4.3.0)");
	logit("pbscheck out of memory");
	die();
}

static void die_envs(void)
{
	errstr("554 to many additional environments defined (#5.3.5)");
	logit("pbscheck control/pbsenvs has to many entries");
	die();
}

static void die_dir(void)
{
	errstr("421 chdir failed (#4.3.0)");
	logit("pbscheck unable to open current directory");
	die();
}

static void die_dirback(void)
{
	errstr("421 chdir failed (#4.3.0)");
	logit("pbscheck unable to switch back to source directory");
	die();
}

