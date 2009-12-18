/*
 * Copyright (c) 2000-2004 Claudio Jeker,
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
#include <errno.h>
#include <unistd.h>
#include "byte.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "pbsexec.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "sgetopt.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"

#include "auth_mod.h"

#ifndef PORT_POP3 /* this is for testing purposes */
#define PORT_POP3	110
#endif

const unsigned int auth_port = PORT_POP3;

#define UP_LEN 513
static char auth_up[UP_LEN];
static int auth_argc;
static char **auth_argv;

void
auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
{
	char		*l, *p;
	unsigned int	uplen, u;
	int		n, opt;

	while ((opt = getopt(argc, argv, "d:")) != opteof) {
		switch (opt) {
		case 'd':
			pbstool = optarg;
			break;
		default:
			auth_error(AUTH_CONF);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		auth_error(AUTH_CONF);
	auth_argc = argc;
	auth_argv = argv;
	
	for (uplen = 0;;) {
		do {
			n = subread(3, auth_up + uplen,
			    sizeof(auth_up) - uplen);
		} while (n == -1 && errno == EINTR);
		if (n == -1)
			auth_error(ERRNO);
		if (n == 0) break;
		uplen += n;
		if (uplen >= sizeof(auth_up))
			auth_error(PANIC);
	}
	close(3);
	auth_up[uplen++] = '\0';
	
	u = 0;
	l = auth_up;
	while (auth_up[u++]) ;
	if (u == uplen)
		auth_error(NEEDED);
	p = auth_up + u;
	while (auth_up[u++]) ;
	if (u == uplen)
		auth_error(NEEDED);

	if (!stralloc_copys(login, l))
		auth_error(ERRNO);
	if (!stralloc_0(login)) 
		auth_error(ERRNO);

	if (!stralloc_copys(authdata, p))
		auth_error(ERRNO);
	if (!stralloc_0(authdata))
		auth_error(ERRNO);

	/* up no longer needed so delete it */
	byte_zero(auth_up, sizeof(auth_up));
}

void
auth_fail(const char *login, int reason)
{
	/* in the qmail-pop3 chain it is not possible to have multiples 
	 * authentication modules. So lets exit with the correct number ... */
	/* In this case we can use auth_error() */
	logit(2, "warning: auth_fail: user %s failed\n", login);
	auth_error(reason);
}

void
auth_success(const char *login)
{
	/* pop befor smtp */
	pbsexec();
	
	/* start qmail-pop3d */
	execvp(*auth_argv,auth_argv);

	auth_error(AUTH_EXEC);
	/* end */
}

void auth_error(int errnum)
{
	/*
	 * See qmail-popup.c for exit codes meanings.
	 */
	logit(2, "warning: auth_error: authorization failed (%s)\n",
		   qldap_err_str(errnum));

	if (errnum == AUTH_CONF) _exit(1);
	if (errnum == TIMEOUT || errnum == LDAP_BIND_UNREACH) _exit(2);
	if (errnum == BADPASS || errnum == NOSUCH) _exit(3);
	if (errnum == NEEDED || errnum == ILLVAL || errnum == BADVAL) _exit(25);
	if (errnum == ACC_DISABLED) _exit(4);
	if (errnum == BADCLUSTER) _exit(5);
	if (errnum == MAILDIR_CORRUPT) _exit(6);
	if (errnum == MAILDIR_FAILED) _exit(61);
	if (errnum == MAILDIR_NONEXIST) _exit(62);
	if (errnum == AUTH_EXEC) _exit(7);
	if (errnum == ERRNO && errno == error_nomem) _exit(8);
	_exit(111);
}

char *
auth_aliasempty(void)
{
	if (auth_argc > 0)
		return auth_argv[auth_argc-1];
	return (char *)0;
}

#ifdef QLDAP_CLUSTER
static void get_ok(int);

static void get_ok(int fd)
/* get the ok for the next command, wait for "+OK.*\r\n" */
/* This should be a mostly correct solution (adapted from fetchmail) */
{
#define AUTH_TIMEOUT 10 /* 10 sec timeout */
#define OK_LEN 512      /* max length of response (RFC1939) */
	char ok[OK_LEN];
	char *c;
	int  len;
	int  i;

	/* first get one single line from the other pop server */
	len = timeoutread(AUTH_TIMEOUT, fd, ok, OK_LEN);
	if (len == -1) 
		auth_error(ERRNO);
	if (len != 0) {
		c = ok;
		if (*c == '+' || *c == '-')
			c++;
		else
			auth_error(BADCLUSTER);
		for (i = 1; i < len /* paranoia */ && 
				('A' < *c && *c < 'Z') ; ) { i++; c++; }

		if (i < len) {
			*c = '\0';
			if (str_diff(ok, "+OK") == 0)
				return;
			else if (str_diffn(ok, "-ERR", 4))
				/* other server is not happy */
				auth_error(BADCLUSTER);
		}
	}
	/* ARRG, very strange POP3 answer */
	auth_error(BADCLUSTER);
}

void auth_forward(int fd, char *login, char *passwd)
{
	char buf[512];
	substdio ss;

	substdio_fdbuf(&ss,subwrite,fd,buf,sizeof(buf));
	get_ok(fd);
	substdio_puts(&ss, "user "); 
	substdio_puts(&ss, login);
	substdio_puts(&ss, "\r\n");
	substdio_flush(&ss);
	get_ok(fd);
	substdio_puts(&ss, "pass "); 
	substdio_puts(&ss, passwd); 
	substdio_puts(&ss, "\r\n");
	substdio_flush(&ss);

}

#endif /* QLDAP_CLUSTER */

