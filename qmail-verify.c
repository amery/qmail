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
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include "auto_break.h"
#include "byte.h"
#include "case.h"
#include "cdb.h"
#include "error.h"
#include "getln.h"
#include "localdelivery.h"
#include "open.h"
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
	if (substdio_puts(subfdout, "ZOut of memory in qmail-verify.") == -1)
		die_write();
	if (substdio_putflush(subfdout, "", 1) == -1)
		die_write();
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

int
temp_sys(void)
{
	if (substdio_puts(subfdout,
	    "ZTemporary failure in qmail-verify.") == -1)
		die_write();
	if (substdio_putflush(subfdout, "", 1) == -1)
		die_write();
	return -1;
}

int
temp_nfs(void)
{
	if (substdio_puts(subfdout, "ZNFS failure in qmail-verify.") == -1)
		die_write();
	if (substdio_putflush(subfdout, "", 1) == -1)
		die_write();
	return -1;
}

void
die_cdb(void)
{
	if (substdio_puts(subfdout,
	    "ZTrouble reading users/cdb in qmail-verify.") == -1)
		die_write();
	if (substdio_putflush(subfdout, "", 1) == -1)
		die_write();
	_exit(111);
}

int lookup(stralloc *);
int lookup_cdb(const char *);
int lookup_passwd(const char *);


int timeout = 5;
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
		localdelivery_init,
		0 };

int
main(int argc, char **argv)
{
	int match;
	unsigned int at;

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

		at = byte_rchr(line.s,line.len,'@');
		if (at >= line.len) {
			if (substdio_puts(subfdout, "DSorry, address must "
			    "include host name. (#5.1.3)") == -1)
				die_write();
			if (substdio_putflush(subfdout, "", 1) == -1)
				die_write();
			continue;
		}

		switch (lookup(&line)) {
		case 0:
			if (localdelivery()) {
				/*
				 * Do the local address lookup.
				 */
				line.s[at] = '\0';
				if (lookup_cdb(line.s) == 1)
					break;
				if (lookup_passwd(line.s) == 1)
					break;
			}
			/* Sorry, no mailbox here by that name. */
			if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
				die_write();
			if (substdio_putflush(subfdout, "", 1) == -1)
				die_write();
			break;
		case 1:
		default:
			break;
		}
	} while (1);

	return 0;
}

int
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
			return (-1);
		case FAILED:
			/* ... again temporary */
			temp_fail();
			return (-1);
		case NOSUCH:
			break;
		}
	} while (rv != OK && !done);
	/* reset filter_mail */
	filter_mail(0, 0);

	/* nothing found, try a local lookup or a alias delivery */
	if (rv == NOSUCH) {
		qldap_free_results(q);
		return (0);
	}

	/* check if the ldap entry is active */
	rv = qldap_get_status(q, &status);
	if (rv != OK) {
		temp_fail();
		return (-1);
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
		return (1);
	} else if (status == STATUS_DELETE) {
		/* Sorry, no mailbox here by that name. (#5.1.1) */
		if (substdio_puts(subfdout,
			    "DSorry, no mailbox here by that name. "
			    "(#5.1.1)") == -1)
			die_write();
		if (substdio_putflush(subfdout, "", 1) == -1)
			die_write();
		qldap_free_results(q);
		return (1);
	}

	/* OK */
	if (substdio_putflush(subfdout, "K", 1) == -1)
		die_write();
	qldap_free_results(q);
	return (1);
}

void
cleanup(void)
{
	if (q != 0)
		qldap_free(q);
	q = 0;
}

stralloc lower = {0};
stralloc wildchars = {0};
struct cdb cdb;

int
lookup_cdb(const char *mail)
{
	int	fd;
	int	flagwild;
	int	r;

	if (!stralloc_copys(&lower, "!")) die_nomem();
	if (!stralloc_cats(&lower, mail)) die_nomem();
	if (!stralloc_0(&lower)) die_nomem();
	case_lowerb(lower.s, lower.len);

	fd = open_read("users/cdb");
	if (fd == -1)
		if (errno != error_noent)
			die_cdb();

	if (fd != -1) {
		uint32 dlen;
		unsigned int i;

		cdb_init(&cdb, fd);
		r = cdb_seek(&cdb, "", 0, &dlen);
		if (r != 1)
			die_cdb();

		if (!stralloc_ready(&wildchars, (unsigned int) dlen))
			die_nomem();
		wildchars.len = dlen;
		if (cdb_bread(&cdb, wildchars.s, wildchars.len) == -1)
			die_cdb();

		i = lower.len;
		flagwild = 0;

		do {
			/* i > 0 */
			if (!flagwild || i == 1 || byte_chr(wildchars.s,
			    wildchars.len, lower.s[i - 1]) < wildchars.len) {
				r = cdb_seek(&cdb,lower.s,i,&dlen);
				if (r == -1)
					die_cdb();
				if (r == 1) {
					/* OK */
					if (substdio_putflush(subfdout, "K",
					    1) == -1)
						die_write();
					
					cdb_free(&cdb);
					close(fd);
					return (1);
				}
			}
			--i;
			flagwild = 1;
		} while (i);

		close(fd);
	}
	return (0);
}

#define GETPW_USERLEN 32

int
lookup_passwd(const char *local)
{
	char username[GETPW_USERLEN];
	struct stat st;
	const char *extension;
	struct passwd *pw;


	extension = local + str_len(local);
	for (; extension >= local; extension--) {
		if ((unsigned long)(extension - local) < sizeof(username))
			if (!*extension || (*extension == *auto_break)) {
				byte_copy(username, extension - local, local);
				username[extension - local] = 0;
				case_lowers(username);
				errno = 0;
				pw = getpwnam(username);
				if (errno == error_txtbsy)
					return temp_sys();
				if (pw && pw->pw_uid != 0) {
					if (stat(pw->pw_dir,&st) == 0 &&
					    st.st_uid == pw->pw_uid) {
						/* OK */
						if (substdio_putflush(subfdout,
						    "K", 1) == -1)
							die_write();
						return (1);
					} else if (error_temp(errno))
						return temp_nfs();
				}
			}
	}
	return (0);
}

