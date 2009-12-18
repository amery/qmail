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
#include <sys/types.h>
#include <unistd.h>
#include "alloc.h"
#include "byte.h"
#include "error.h"
#include "localdelivery.h"
#include "locallookup.h"
#include "output.h"
#include "pbsexec.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "read-ctrl.h"
#include "readwrite.h"
#include "stralloc.h"
#ifdef QLDAP_CLUSTER
#include <sys/socket.h>
#include "dns.h"
#include "ipalloc.h"
#include "ipme.h"
#include "ndelay.h"
#include "qldap-cluster.h"
#include "select.h"
#include "timeoutconn.h"
#endif
#ifdef AUTOHOMEDIRMAKE
#include "dirmaker.h"
#endif
#ifdef AUTOMAILDIRMAKE
#include "mailmaker.h"
#endif


#include "checkpassword.h"
#include "auth_mod.h"

stralloc	loginstr = {0};
stralloc	authdatastr = {0};

ctrlfunc	ctrls[] = {
		qldap_ctrl_login,
		qldap_ctrl_generic,
		localdelivery_init,
#ifdef QLDAP_CLUSTER
		cluster_init,
#endif
#ifdef AUTOHOMEDIRMAKE
		dirmaker_init,
#endif		
		0 };

checkfunc	cfuncs[] = {
	check_ldap,
	check_passwd,
	0
};

void chdir_or_make(char *, char *);

#ifdef QLDAP_CLUSTER
void forward(char *, char *, struct credentials *);
#endif

int
main(int argc, char **argv)
{
	struct	credentials c;
	int r;

	log_init(STDERR, ~256, 0);	/* XXX limited so that it is not
					   possible to get passwords via 
					   debug on production systems.
					 */
	if (read_controls(ctrls) == -1)
		auth_error(AUTH_CONF);

	auth_init(argc, argv, &loginstr, &authdatastr);
	logit(256, "auth_init: login=%s, authdata=%s\n",
	    loginstr.s, authdatastr.s);

	if (authdatastr.len <= 1) {
		logit(1, "alert: null password.\n");
		auth_fail(loginstr.s, BADPASS);
	}
	
	byte_zero(&c, sizeof(c));
	r = check(cfuncs, &loginstr, &authdatastr, &c, 0);
	switch (r) {
	case OK:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		change_uid(c.uid, c.gid);
		setup_env(loginstr.s, &c);
		chdir_or_make(c.home.s, c.maildir.s);
		auth_success(loginstr.s);
	case FORWARD:
#ifdef QLDAP_CLUSTER
		change_uid(-1, -1);
		setup_env(loginstr.s, &c);
		forward(loginstr.s, authdatastr.s, &c);
		/* does not return */
#else
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		/* system error, now way out ... module likes to forward
		   but we don't have support for it. */
		auth_error(r);
#endif
	case NOSUCH: /* FALLTHROUGH */
	case BADPASS:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		auth_fail(loginstr.s, r);
	default:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		/* system error, now way out ... */
		auth_error(r);
	}
		
	auth_error(PANIC);
	return 1; /* should never get here */
}

void
chdir_or_make(char *home, char *maildir)
{
	char	*md;

	if (maildir == (char *)0 || *maildir == '\0')
		md = auth_aliasempty();
	else
		md = maildir;

	/* ... go to home dir and create it if needed */
	if (chdir(home) == -1) {
#ifdef AUTOHOMEDIRMAKE
		logit(8, "makeing homedir for %s %s\n", home, md);

		switch (dirmaker_make(home, md)) {
		case OK:
			break;
		case MAILDIR_CRASHED:
			logit(2, "warning: dirmaker failed: program crashed\n");
			auth_error(MAILDIR_FAILED);
		case MAILDIR_FAILED:
			logit(2, "warning: dirmaker failed: bad exit status\n");
			auth_error(MAILDIR_FAILED);
		case MAILDIR_UNCONF:
			logit(2, "warning: dirmaker failed: not configured\n");
			auth_error(MAILDIR_NONEXIST);
		case MAILDIR_HARD:
			logit(2, "warning: dirmaker failed: hard error\n");
		case ERRNO:
		default:
			logit(2, "warning: dirmaker failed (%s)\n",
			    error_str(errno));
			auth_error(MAILDIR_FAILED);
		}
		if (chdir(home) == -1) {
			logit(2, "warning: 2nd chdir failed: %s\n",
			    error_str(errno));
			auth_error(MAILDIR_FAILED);
		}
		logit(32, "homedir successfully made\n");
#else
		logit(2, "warning: chdir failed: %s\n", error_str(errno));
		auth_error(MAILDIR_NONEXIST);
#endif
	}
#ifdef AUTOMAILDIRMAKE
	switch (maildir_make(md)) {
	case OK:
		break;
	case MAILDIR_CORRUPT:
		logit(2, "warning: maildir_make failed (%s)\n",
		    "maildir seems to be corrupt");
		auth_error(MAILDIR_CORRUPT);
	case ERRNO:
	default:
		logit(2, "warning: maildir_make failed (%s)\n",
		    error_str(errno));
		auth_error(MAILDIR_FAILED);
	}
#endif
}

#ifdef QLDAP_CLUSTER
#define COPY_BUF_SIZE	8192
static void copyloop(int, int, int, int);

static void
copyloop(int infdr, int infdw, int outfd, int timeout)
{
	fd_set	rfds, wfds;
	struct	timeval tv;
	int	maxfd;	/* Maximum numbered fd used */
	int	r, inpos = 0, outpos = 0;
	int	inok = 1, outok = 1;
	char	*inbuf, *outbuf;

	inbuf = alloc(COPY_BUF_SIZE);
	outbuf = alloc(COPY_BUF_SIZE);

	if (inbuf == (char *)0 || outbuf == (char *)0) {
		logit(1, "copyloop: %s\n", error_str(errno));
		close(infdr);
		close(infdw);
		close(outfd);
		return;
	}

	maxfd = infdr > infdw ? infdr : infdw;
	maxfd = (maxfd > outfd ? maxfd : outfd) + 1;

	while (1) {
		/* file descriptor bits */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (inok && inpos < COPY_BUF_SIZE)
			FD_SET(infdr, &rfds);
		if (outpos != 0)
			FD_SET(infdw, &wfds);
		if (outok && outpos < COPY_BUF_SIZE)
			FD_SET(outfd, &rfds);
		if (inpos != 0)
			FD_SET(outfd, &wfds);

		/* Set up timeout */
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		r = select(maxfd, &rfds, &wfds, (fd_set *)0, &tv);
		if (r == -1) {
			logit(1, "copyloop: select: %s\n",
			    error_str(errno));
			break;
		} else if (r == 0) {
			logit(32, "copyloop: select timeout\n");
			break;
		}

		if (FD_ISSET(infdr, &rfds)) {
			if ((r = subread(infdr, inbuf + inpos,
			    COPY_BUF_SIZE - inpos)) == -1) {
				if (errno == error_intr) continue;
				logit(1, "copyloop: read: %s\n",
				    error_str(errno));
				break;
			}
			if (r == 0)
				inok = 0;
			inpos += r;
		}
		if (FD_ISSET(outfd, &rfds)) {
			if ((r = subread(outfd, outbuf + outpos,
			    COPY_BUF_SIZE - outpos)) == -1) {
				if (errno == error_intr) continue;
				logit(1, "copyloop: read: %s\n",
				    error_str(errno));
				break;
			}
			if (r == 0)
				outok = 0;
			outpos += r;
		}
		if (FD_ISSET(infdw, &wfds)) {
			if ((r = subwrite(infdw, outbuf, outpos)) == -1) {
				if (errno == error_intr) continue;
				logit(1, "copyloop: write: %s\n",
				    error_str(errno));
				break;
			}
			if (r != outpos)
				byte_copy(outbuf, outpos - r, outbuf + r);
			outpos -= r;
		}
		if (FD_ISSET(outfd, &wfds)) {
			if ((r = subwrite(outfd, inbuf, inpos)) == -1) {
				if (errno == error_intr) continue;
				logit(1, "copyloop: write: %s\n",
				    error_str(errno));
				break;
			}
			if (r != inpos)
				byte_copy(inbuf, inpos - r, inbuf + r);
			inpos -= r;
		}

		if (inok == 0 && inpos == 0)
			/* half close forwarding channel */
			shutdown(outfd, SHUT_WR);

		if (outpos == 0 && outok == 0)
			/*
			 * Can not half close channel to client so finish the
			 * communication. Server is no longer intrested anyway.
			 */
			break;
	}

	close(infdr);
	close(infdw);
	close(outfd);
}

void
forward(char *name, char *passwd, struct credentials *c)
{
	struct	ip_address outip;
	ipalloc	ip = {0};
	int	ffd;
	int	timeout = 31*60; /* ~30 min timeout RFC1730 */
	int	ctimeout = 30;
	
	/* pop befor smtp */
	pbsexec();

	if (!ip_scan("0.0.0.0", &outip))
		auth_error(ERRNO);

	dns_init(0);
	switch (dns_ip(&ip,&c->forwarder)) {
		case DNS_MEM:
			auth_error(ERRNO);
		case DNS_SOFT:
		case DNS_HARD:
			auth_error(BADCLUSTER);
		case 1:
			if (ip.len <= 0)
				auth_error(BADCLUSTER);
	}
	/* 
	   20010523 Don't check if only one IP is returned, so it is
	   possible to have a cluster node consisting of multiple machines. 
	   XXX If your mailhost is bad (bad entries in ldap) you will get
	   bad loops, the only limit is the tcpserver concurrency limit.
	   20030627 Could we use the ipme stuff of qmail-remote, to make
	   single hop loops impossible? Let's try it.
	 */
	if (ipme_is(&ip.ix[0].ip) == 1)
		auth_error(BADCLUSTER);

	ffd = socket(AF_INET, SOCK_STREAM, 0);
	if (ffd == -1)
		auth_error(ERRNO);
	
	if (timeoutconn(ffd, &ip.ix[0].ip, &outip, auth_port, ctimeout) != 0)
		auth_error(ERRNO);
	
	/* We have a connection, first send user and pass */
	auth_forward(ffd, name, passwd);
	copyloop(0, 1, ffd, timeout);

	_exit(0); /* all went ok, exit normaly */
}

#endif /* QLDAP_CLUSTER */

