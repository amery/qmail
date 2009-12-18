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
#include <unistd.h>
#include "error.h"
#include "getln.h"
#include "output.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "stralloc.h"
#include "subfd.h"
#include "substdio.h"
#include "timeoutread.h"

struct qldap *q;

void cleanup(void);
void
die_read(void)
{
	cleanup();
	_exit(1);
}
void
die_write(void)
{
	cleanup();
	_exit(1);
}
void
die_nomem(void)
{
	cleanup();
	_exit(111);
}
void
die_timeout(void)
{
	cleanup();
	_exit(111);
}
void
die_temp(void)
{
	cleanup();
	_exit(111);
}
void
die_control(void)
{
	_exit(100);
}
void
temp_fail(void)
{
	if (substdio_putflush(subfdout, "Z", 2) == -1)
		die_write();
	qldap_free_results(q);
}

void lookup(stralloc *mail);


int timeout = 3;
int
saferead(int fd, void *buf, int len)
{
	return timeoutread(timeout,fd,buf,len);
}

char ssinbuf[512];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

stralloc line = {0};
ctrlfunc	ctrls[] = {
		qldap_ctrl_trylogin,
		qldap_ctrl_generic,
		0 };

int
main(int argc, char **argv)
{
	int match;

	log_init(STDERR, ~256, 0);

	if (read_controls(ctrls) == -1)
		die_control();
	
	q = 0;
	do {
		if (getln(&ssin, &line, &match, '\0') != 0) {
			if (errno != error_timeout)
				die_read();
			cleanup();
			continue;
		}
		if (!match) {
			cleanup(); /* other side closed pipe */
			break;
		}
		logit(32, "qmail-verfiy: verifying %S\n", &line);
		lookup(&line);
	} while (1);
	return 0;
}

void
lookup(stralloc *mail)
{
	const char *attrs[] = {  LDAP_ISACTIVE, 0 };
	char *f;
	int done;
	int status;
	int rv;

	if (q == 0) {
		q = qldap_new();
		if (q == 0)
			die_nomem();

		rv = qldap_open(q);
		if (rv != OK) die_temp();
		rv = qldap_bind(q, 0, 0);
		if (rv != OK) die_temp();
	}
	
	/*
	 * this handles the "catch all" and "-default" extension 
	 * but also the normal eMail address.
	 * Code handels also mail addresses with multiple '@' safely.
	 * at = index to last @ sign in mail address
	 * escaped = ldap escaped mailaddress
	 * len = length of escaped mailaddress
	 * i = position of current '-' or '@'
	 */
	done = 0;
	do {
		f = filter_mail(mail->s, &done);
		if (f == (char *)0) die_nomem();

		logit(16, "ldapfilter: '%s'\n", f);

		/* do the search for the email address */
		rv = qldap_lookup(q, f, attrs);
		switch (rv) {
		case OK:
			break; /* something found */
		case TIMEOUT:
			/* temporary error but give up so that the
			 * ldap server can recover */
			die_timeout();
		case TOOMANY:
#ifdef DUPEALIAS
			if (substdio_putflush(subfdout, "K", 1) == -1)
				die_write();
			qldap_free_results(q);
#else
			/* admin error, also temporary */
			temp_fail();
#endif
			return;
		case FAILED:
			/* ... again temporary */
			temp_fail();
			return;
		case NOSUCH:
			break;
		}
	} while (rv != OK && !done);
	/* reset filter_mail */
	filter_mail(0, 0);

	/* nothing found, try a local lookup or a alias delivery */
	if (rv == NOSUCH) {
		/* Sorry, no mailbox here by that name. (#5.1.1) */
		if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	}

	/* check if the ldap entry is active */
	rv = qldap_get_status(q, &status);
	if (rv != OK) {
		temp_fail();
		return;
	}
	if (status == STATUS_BOUNCE) {
		/* Mailaddress is administratively disabled. (#5.2.1) */
		if (substdio_puts(subfdout,
			    "DMailaddress is administratively disabled. "
			    "(#5.2.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	} else if (status == STATUS_DELETE) {
		/* Sorry, no mailbox here by that name. (#5.1.1) */
		if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return;
	}

	/* OK */
	if (substdio_putflush(subfdout, "K", 1) == -1)
		die_write();
	qldap_free_results(q);
}

void
cleanup(void)
{
	if (q != 0)
		qldap_free(q);
	q = 0;
}

