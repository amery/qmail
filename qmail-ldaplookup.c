/*
 * Copyright (c) 2000-2004 Andre Oppermann, Claudio Jeker,
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
#include <pwd.h>
#include <unistd.h>

#include "alloc.h"
#include "auto_usera.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "error.h"
#include "localdelivery.h"
#include "output.h"
#include "passwd.h"
#include "qldap.h"
#include "qldap-cluster.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "scan.h"
#include "sgetopt.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "subfd.h"
#include "substdio.h"
#ifdef AUTOHOMEDIRMAKE
#include "dirmaker.h"
#endif

#define FATAL "qmail-ldaplookup: fatal: "
#define WARN "qmail-ldaplookup: warning: "

void
temp_nomem(void)
{
        strerr_die2x(111, FATAL, "Out of memory.");
}

void
usage(void) 
{
	output(subfderr,
	    "usage:"
	    "\t%s [-d level] [-D binddn -w passwd] -u uid [-p passwd]\n"
	    "\t%s [-d level] [-D binddn -w passwd] -m mail\n"
	    "\t%s [-d level] [-D binddn -w passwd] -f ldapfilter\n",
	    optprogname, optprogname, optprogname, optprogname);
	output(subfderr, "options:\n"
	    "\t-d level \tsets log-level to level\n"
	    "\t-u uid   \tsearch for user id uid (pop3/imap lookup)\n"
	    "\t-p passwd\tpassword for user id lookups (only by root)\n"
	    "\t-m mail  \tlookup the mailaddress\n"
	    "\t-D binddn\tbind DN\n"
	    "\t-w passwd\tbind password\n");
	_exit(1);
}

void fail(qldap *, const char *, int);
void unescape(char *, stralloc *);


ctrlfunc ctrls[] = {
  qldap_ctrl_trylogin,
  qldap_ctrl_generic,
  localdelivery_init,
#ifdef QLDAP_CLUSTER
  cluster_init,
#endif
#ifdef AUTOHOMEDIRMAKE
  dirmaker_init,
#endif
  0
};

stralloc dn = {0};
stralloc foo = {0};
stralloc bar = {0};

int main(int argc, char **argv)
{
	enum { unset, uid, mail, filter } mode = unset;
	qldap	*q, *qpw;
	struct passwd *pw;
	char	*passwd = 0, *value = 0;
	char	*bindpw = 0, *binddn = 0;
	char	*f, *s;
	int	opt, r, done, status, id;
	unsigned int j, slen;
	unsigned long size, count, maxsize;
	
	const char *attrs[] = { LDAP_MAIL,
				LDAP_MAILALTERNATE,
				LDAP_UID,
				LDAP_QMAILUID,
				LDAP_QMAILGID,
				LDAP_ISACTIVE,
				LDAP_MAILHOST,
				LDAP_MAILSTORE,
				LDAP_HOMEDIR,
				LDAP_QUOTA_SIZE,
				LDAP_QUOTA_COUNT,
				LDAP_FORWARDS,
				LDAP_PROGRAM,
				LDAP_MODE,
				LDAP_REPLYTEXT,
				LDAP_DOTMODE,
				LDAP_MAXMSIZE,
				LDAP_OBJECTCLASS,
#if 0
				LDAP_GROUPCONFIRM,
				LDAP_GROUPMEMONLY,
				LDAP_GROUPCONFRIMTEXT,
				LDAP_GROUPMODERATTEXT,
				LDAP_GROUPMODERATDN,
				LDAP_GROUPMODERAT822,
				LDAP_GROUPMEMBERDN,
				LDAP_GROUPMEMBER822,
				LDAP_GROUPMEMBERFILTER,
#endif
				LDAP_PASSWD,
				0};

	while ((opt = getopt(argc, argv, "d:D:u:m:p:f:w:")) != opteof)
		switch (opt) {
		case 'd':
			if (env_put2("LOGLEVEL", optarg) == 0)
				strerr_die2sys(1, FATAL, "setting loglevel: ");
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'u':
			if (value != 0)
				usage();
			value = optarg;
			mode = uid;
			break;
		case 'm':
			if (value != 0)
				usage();
			value = optarg;
			mode = mail;
			break;
		case 'f':
			if (value != 0)
				usage();
			value = optarg;
			mode = filter;
			break;
		case 'p':
			if (geteuid() != 0)
				strerr_die2x(1, FATAL,
				    "only the superuser may comapre passwords");
			passwd = optarg;
			break;
		case 'w':
			bindpw = optarg;
			break;
		default:
			usage();
		}
	if (argc != optind) usage();
	if (bindpw && !binddn) usage();
	
	log_init(STDERR, -1, 0);

	if (read_controls(ctrls) != 0)
		strerr_die2sys(111, FATAL, "unable to read controls: ");
	
	q = qldap_new();
	if (q == 0)
		strerr_die2sys(111, FATAL, "qldap_new failed: ");
	qpw = qldap_new();
	if (qpw == 0)
		strerr_die2sys(111, FATAL, "qldap_new failed: ");
	
	r = qldap_open(q);
	if (r != OK) fail(q, "qldap_open", r);
	r = qldap_open(qpw);
	if (r != OK) fail(qpw, "qldap_open", r);
	r = qldap_bind(q, binddn, bindpw);
	if (r != OK) fail(q, "qldap_bind", r);

	if (passwd == 0 || mode != uid || qldap_need_rebind() != 0)
		attrs[sizeof(attrs)/4 - 2] = 0; /* password */
	done = 0;
	f = 0;
	do {
		switch (mode) {
		case mail:
			f = filter_mail(value, &done);
			if (value == 0)
				strerr_die2sys(1, FATAL, "building filter: ");
			break;
		case uid:
			f = filter_uid(value);
			done = 1;
			if (value == 0)
				strerr_die2sys(1, FATAL, "building filter: ");
			break;
		case filter:
			f = value;
			break;
		default:
			usage();
		}
		output(subfdout, "Searching ldap for: %s\nunder dn: %s\n",
		    f, qldap_basedn());
		r = qldap_filter(q, f, attrs, qldap_basedn(), SCOPE_SUBTREE);
		if (r != OK) fail(q, "qldap_filter", r);

		r = qldap_count(q);
		switch (r) {
		case -1:
			fail(q, "qldap_count", FAILED);
		case 0:
			output(subfdout, "No entries found.\n");
			qldap_free(q);
			/* TODO hook for local lookups. */
			return 0;
		case 1:
			output(subfdout, "Found %i entry:\n", r);
			break;
		default:
			output(subfdout, "Found %i entries:\n", r);
			if (mode == uid || mode == uid) {
				output(subfdout,
				    "Uh-oh: multiple entries found but "
				    "should be unique!\n");
				passwd = 0;
			}
			break;
		}
		output(subfdout, "\n");
	} while (r == 0 && !done);

	r = qldap_first(q);
	if (r != OK) fail(q, "qldap_first", r);;
	do {
		r = qldap_get_dn(q, &dn);
		if (r != OK) fail(q, "qldap_get_dn", r);
		output(subfdout, "dn: %s\n"
		    "-------------------------------------------------------\n",
		    dn.s);
		
		r = qldap_get_attr(q, LDAP_OBJECTCLASS, &foo, MULTI_VALUE);
		if (r != OK) fail(q, "qldap_get_attr(" LDAP_OBJECTCLASS ")", r);
		unescape(foo.s, &bar);
		s = bar.s;
		slen = bar.len-1;
		for(;;) {
			output(subfdout, "%s: %s\n",LDAP_OBJECTCLASS ,s);
			j = byte_chr(s,slen,0);
			if (j++ >= slen) break;
			s += j; slen -= j;
		}
		
		r = qldap_get_attr(q, LDAP_MAIL, &foo, SINGLE_VALUE);
		if (r != OK) fail(q, "qldap_get_attr(" LDAP_MAIL ")", r);
		output(subfdout, "%s: %s\n", LDAP_MAIL, foo.s);

		r = qldap_get_attr(q, LDAP_MAILALTERNATE, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MAILALTERNATE ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n",
				    LDAP_MAILALTERNATE, s);
				j = byte_chr(s,slen,0);
				if (j++ >= slen) break;
				s += j; slen -= j;
			}
		}
		
		r = qldap_get_user(q, &foo);
		if (r != OK && r != NOSUCH) fail(q, "qldap_get_user", r);
		if (r == OK)
			output(subfdout, "%s: %s\n", LDAP_UID, foo.s);
		else
			output(subfdout, "%s: undefined "
			    "(forward only account required)\n", LDAP_UID);

		r = qldap_get_status(q, &status);
		if (r != OK) fail(q, "qldap_get_status", r);
		switch (status) {
		case STATUS_BOUNCE:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_BOUNCE);
			break;
		case STATUS_NOACCESS:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_NOACCESS);
			break;
		case STATUS_OK:
			output(subfdout, "%s: %s\n",
			    LDAP_ISACTIVE, ISACTIVE_ACTIVE);
			break;
		case STATUS_UNDEF:
			output(subfdout, "%s: %s\n", LDAP_ISACTIVE,
			    "undefined -> active");
			break;
		default:
			strerr_warn2(WARN,
			    "qldap_get_status returned unknown status", 0);
		}
		
		r = qldap_get_attr(q, LDAP_MAILHOST, &foo, SINGLE_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MAILHOST ")", r);
		if (r == OK) {
			output(subfdout, "%s: %s\n", LDAP_MAILHOST, foo.s);
			/*
			 * TODO we could check if we are in cluster mode and 
			 * if we would redirect to a differnet host
			 */
		} else
			output(subfdout, "%s: undefined\n", LDAP_MAILHOST);

		/* get the path of the maildir or mbox */
		r = qldap_get_mailstore(q, &foo, &bar);
		switch (r) {
		case OK:
			output(subfdout, "homeDirectory: %s\n", foo.s);
			if (bar.len > 0)
				output(subfdout, "aliasEmpty: %s\n", bar.s);
			else
				output(subfdout, "aliasEmpty: using default\n");
			break;
		case NEEDED:
			output(subfdout,
			    "forward only delivery via alias user\n");
			pw = getpwnam(auto_usera);
			if (!pw)
				strerr_die4x(100, FATAL,
				    "Aiiieeeee, now alias user '",
				    auto_usera, "'found in /etc/passwd.");
			output(subfdout, "alias user: %s\n", pw->pw_name);
			output(subfdout, "alias user uid: %i\n", pw->pw_uid);
			output(subfdout, "alias user gid: %i\n", pw->pw_gid);
			output(subfdout, "alias user home: %s\n", pw->pw_dir);
			output(subfdout, "alias user aliasempty: %s\n",
			    ALIASDEVNULL);
			/* get the forwarding addresses */
			r = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
			if (r != OK)
				fail(q, "qldap_get_attr("
				    LDAP_FORWARDS ") for forward only user", r);
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_FORWARDS, s);
				j = byte_chr(s,slen,0);
				if (j++ >= slen) break;
				s += j; slen -= j;
			}
			goto next;
		default:
			fail(q, "qldap_get_mailstore", r);
		}
		
		r = qldap_get_dotmode(q, &foo);
		if (r != OK) fail(q, "qldap_get_dotmode", r);
		output(subfdout, "%s: %s\n", LDAP_DOTMODE, foo.s);

		r = qldap_get_uid(q, &id);
		if (r != OK) fail(q, "qldap_get_uid", r);
		output(subfdout, "%s: %i\n", LDAP_QMAILUID, id);
		
		r = qldap_get_gid(q, &id);
		if (r != OK) fail(q, "qldap_get_gid", r);
		output(subfdout, "%s: %i\n", LDAP_QMAILGID, id);
		
		r = qldap_get_quota(q, &size, &count, &maxsize);
		if (r != OK) fail(q, "qldap_get_quota", r);
		output(subfdout, "%s: %u%s\n", LDAP_QUOTA_SIZE, size,
		    size==0?" (unlimited)":"");
		output(subfdout, "%s: %u%s\n", LDAP_QUOTA_COUNT, count,
		    count==0?" (unlimited)":"");
		output(subfdout, "%s: %u%s\n", LDAP_MAXMSIZE, maxsize,
		    maxsize==0?" (unlimited)":"");

		r = qldap_get_attr(q, LDAP_MODE, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_MODE ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				if (case_diffs(MODE_FORWARD, s) &&
				    case_diffs(MODE_REPLY, s) &&
				    case_diffs(MODE_NOLOCAL, s) &&
				    case_diffs(MODE_NOMBOX, s) &&
				    case_diffs(MODE_NOFORWARD, s) &&
				    case_diffs(MODE_NOPROG, s) &&
				    case_diffs(MODE_LOCAL, s) &&
				    case_diffs(MODE_FORWARD, s) &&
				    case_diffs(MODE_PROG, s) &&
				    case_diffs(MODE_NOREPLY, s))
					strerr_warn4(WARN,
					    "undefined mail delivery mode: ",
					    s," (ignored).", 0);
				else if (!case_diffs(MODE_FORWARD, s))
					strerr_warn4(WARN,
					    "mail delivery mode: ",
					    s," should not be used "
					    "(used internally).", 0);
				output(subfdout, "%s: %s\n", LDAP_MODE, s);
				j = byte_chr(s,slen,0);
				if (j++ >= slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_FORWARDS ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_FORWARDS, s);
				j = byte_chr(s,slen,0);
				if (j++ >= slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_PROGRAM, &foo, MULTI_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_PROGRAM ")", r);
		if (r == OK) {
			unescape(foo.s, &bar);
			s = bar.s;
			slen = bar.len-1;
			for(;;) {
				output(subfdout, "%s: %s\n", LDAP_PROGRAM, s);
				j = byte_chr(s,slen,0);
				if (j++ >= slen) break;
				s += j; slen -= j;
			}
		}

		r = qldap_get_attr(q, LDAP_REPLYTEXT, &foo, SINGLE_VALUE);
		if (r != OK && r != NOSUCH)
			fail(q, "qldap_get_attr(" LDAP_REPLYTEXT ")", r);
		if (r == OK)
			output(subfdout, "%s:\n=== begin ===\n%s\n"
			    "=== end ===\n", LDAP_REPLYTEXT, foo.s);
		else
			output(subfdout, "%s: undefined\n", LDAP_REPLYTEXT);

		if (mode == uid && passwd != 0) {
			if (qldap_need_rebind() == 0) {
				r = qldap_get_attr(q, LDAP_PASSWD,
				    &foo, SINGLE_VALUE);
				if (r != OK) fail(q, "qldap_get_attr("
				    LDAP_PASSWD ")", r);
				r = cmp_passwd(passwd, foo.s);
			} else {
				r = qldap_rebind(qpw, dn.s, passwd);
				switch (r) {
				case OK:
					r = OK;
					break;
				case LDAP_BIND_AUTH:
					r = BADPASS;
					break;
				default:
					break;
				}
			}
			output(subfdout, "\nPASSWORD COMPARE was %s.\n",
			    r == OK?"successful":"NOT successful");
			if (r != OK)
				output(subfdout, "\terror was: %s\n",
				    qldap_err_str(r));
		}

next:
		r = qldap_next(q);
		output(subfdout, "\n\n");
	} while (r == OK);
	if (r != NOSUCH) fail(q, "qldap_next", r);
	qldap_free(q);
	return 0;
}

void
fail(qldap *q, const char *f, int r)
{
	qldap_free(q);
	strerr_die4x(111, FATAL, f ,": ", qldap_err_str(r));
}

void
unescape(char *s, stralloc *t)
{
  if (!stralloc_copys(t, "")) temp_nomem();
  do {
    if (s[0] == '\\' && s[1] == ':') s++;
    else if (s[0] == ':') {
      if (!stralloc_0(t)) temp_nomem();
      continue;
    }
    if (!stralloc_append(t, s)) temp_nomem();
  } while (*s++);
}

