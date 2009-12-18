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
#include <errno.h>
#include <unistd.h>
#include "base64.h"
#include "byte.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "getln.h"
#include "output.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "str.h"
#include "stralloc.h"
#include "subfd.h"
#include "substdio.h"
#include "timeoutread.h"

#include "checkpassword.h"

#include "auth_mod.h"

checkfunc	cfuncs[] = {
	check_ldap,
	0
};

stralloc line = {0};
stralloc plain = {0};

void
auth_init(int argc, char **argv, stralloc *login, stralloc *authdata)
{
	char *s, *smax;
	int match;
	
	if (argc != 1)
		auth_error(AUTH_CONF);
	
	if (getln(subfdin, &line, &match, '\0') != 0)
		auth_error(ERRNO);
	if (!match) auth_error(NEEDED);
	if (!str_diff(line.s, "login")) {
		if (getln(subfdin, &line, &match, '\0') != 0)
			auth_error(ERRNO);
		if (!match) auth_error(NEEDED);
		if (b64_ptons(line.s, login) == -1) auth_error(BADVAL);
		if (getln(subfdin, &line, &match, '\0') != 0)
			auth_error(ERRNO);
		if (!match) auth_error(NEEDED);
		if (b64_ptons(line.s, authdata) == -1) auth_error(BADVAL);
		/* XXX we should check if there is some bad
		 * data in both values */
		if (!stralloc_0(login)) auth_error(ERRNO);
		if (!stralloc_0(authdata)) auth_error(ERRNO);
		return;
	}
	if (!str_diff(line.s, "plain")) {
		/*
		 * plain sends: [authorize-id]\0authenticate-id\0password
		 */
		if (!stralloc_copys(login, "")) auth_error(ERRNO);
		if (!stralloc_copys(authdata, "")) auth_error(ERRNO);
		if (getln(subfdin, &line, &match, '\0') != 0)
			auth_error(ERRNO);
		if (!match) auth_error(NEEDED);
		if (b64_ptons(line.s, &plain) == -1) auth_error(BADVAL);
		s = plain.s; smax = s + plain.len;
		while (*s++ != '\0') if (s >= smax) auth_error(BADVAL);
		do {
			if (!stralloc_append(login, s)) auth_error(ERRNO);
			if (s >= smax) auth_error(BADVAL);
		} while (*s++ != '\0');
		while (*s && s < smax) {
			if (!stralloc_append(authdata, s)) auth_error(ERRNO);
			s++;
		}
		if (!stralloc_0(authdata)) auth_error(ERRNO);
		return;
	}
	auth_error(AUTH_TYPE);
}

void
auth_fail(const char *login, int reason)
{
	logit(2, "warning: auth_fail: user %s failed\n", login);

	if (substdio_putflush(subfdout, "D", 1) == -1) auth_error(ERRNO);
	_exit(0);
}

void
auth_success(const char *login)
{
	if (substdio_put(subfdout, "K", 1) == -1) auth_error(ERRNO);
	if (substdio_puts(subfdout, login) == -1) auth_error(ERRNO);
	if (substdio_putflush(subfdout, "", 1) == -1) auth_error(ERRNO);
	_exit(0);
}

void auth_error(int errnum)
{
	logit(2, "warning: auth_error: authorization failed (%s)\n",
		   qldap_err_str(errnum));
	if (errnum == BADVAL || errnum == NEEDED || errnum == ILLVAL) {
		if (substdio_putflush(subfdout, "Z", 1) == -1)
			auth_error(ERRNO);
		_exit(0);
	}

	_exit(111);
}

char *
auth_aliasempty(void)
{
	return (char *)0;
}

stralloc	loginstr = {0};
stralloc	authdatastr = {0};

ctrlfunc	ctrls[] = {
		qldap_ctrl_trylogin,
		qldap_ctrl_generic,
		0 };

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
	r = check(cfuncs, &loginstr, &authdatastr, &c, 1);
	/* XXX I'm not very happy with this solution but currently this
	 * is the easiest way. This file, auth_mod.c and checkpassword.c
	 * need some refactoring (: */
	switch (r) {
	case OK:
	case FORWARD:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		auth_success(loginstr.s);
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


