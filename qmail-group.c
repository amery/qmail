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

#include "alloc.h"
#include "auto_break.h"
#include "byte.h"
#include "case.h"
#include "coe.h"
#include "control.h"
#include "env.h"
#include "error.h"
#include "fd.h"
#include "fmt.h"
#include "getln.h"
#include "ndelay.h"
#include "now.h"
#include "open.h"
#include "qldap.h"
#include "qldap-errno.h"
#include "qmail.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "readwrite.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"
#include "wait.h"

#define FATAL "qmail-group: fatal: "

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory. (#4.3.0)");
}
void
temp_qmail(char *fn)
{
	strerr_die4sys(111, FATAL, "Unable to open ", fn, ": ");
}
void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message. (#4.3.0)");
}
void
temp_read(void)
{
	strerr_die2x(111, FATAL, "Unable to read message. (#4.3.0)");
}
void
temp_fork(void)
{
	strerr_die2sys(111, FATAL, "Unable to fork: ");
}
void usage(void)
{
	strerr_die1x(100, "qmail-group: usage: qmail-group Maildir");
}

void init(void);
void bouncefx(void);
void reset_sender(void);
void blast(stralloc *, int);
void reopen(void);
void trydelete(void);
void secretary(char *, int);
void explode(qldap *);
void subscribed(qldap *, int);
qldap *ldapgroup(char *, int *, int *, int *);

char *local;
char *host;
char *sender;
stralloc base = {0};
stralloc action = {0};
char *ext;
char *dname;

stralloc recips = {0};
stralloc bounceadmin = {0};
stralloc moderators = {0};
unsigned int nummoderators;


int
main(int argc, char **argv)
{
	qldap *qlc;
	char *maildir;
	int flagm, flagc, flags, flagS;
	
	if (argv[1] == 0) usage();
	if (argv[2] != 0) usage();
	maildir = argv[1];
	
	init();
	/* filter out loops as soon as poosible */
	bouncefx();
	
	flagc = flags = flagS = flagm = 0;
	qlc = ldapgroup(dname, &flagc, &flags, &flagS);

	/* need to distinguish between new messages and responses */
	if (action.s) {
		if (!case_diffs(action.s, "confirm") ||
		    !case_diffs(action.s, "approve") ||
		    !case_diffs(action.s, "reject"))
			secretary(maildir, flagc);
		else if (moderators.s && moderators.len &&
		    !case_diffs(action.s, "moderators") && !(ext && *ext)) {
			/* mail to moderators */
			blast(&moderators, 0);
		} else if (!case_diffs(action.s, "return")) {
			/* bounce form subscribed user */
			blast(&bounceadmin, 0);
		} else if (!case_diffs(action.s, "bounce") && ext && *ext) {
			/* bounce from moderator */
			if (bounceadmin.s && bounceadmin.len)
				blast(&bounceadmin, 0);
			secretary(maildir, flagc);
		} else
			/* bad address */
			strerr_die2x(100, FATAL, "Sorry, no mailbox here "
			    "by that name. (#5.1.1)");
	} else {
		if (flags)
			subscribed(qlc, flagS);
		if (flagc || nummoderators)
			secretary(maildir, flagc);
	}

	reopen();
	explode(qlc);
	qldap_free(qlc);
	
	/* does not return */
	blast(&recips, 1);
	return 111;
}

stralloc grouplogin = {0};
stralloc grouppassword = {0};

int
init_controls(void)
{
	switch (control_readline(&grouplogin, "control/ldapgrouplogin")) {
	case 0:
		return 0;
	case 1:
		break;
	default:
		return -1;
	}
	if (!stralloc_0(&grouplogin)) return -1;

	if (control_rldef(&grouppassword, "control/ldapgrouppassword",
		    0, "") == -1)
		return -1;
	if (!stralloc_0(&grouppassword)) return -1;

	return 0;
}

ctrlfunc ctrls[] = {
	qldap_ctrl_trylogin,
	qldap_ctrl_generic,
	init_controls,
	0
};

stralloc dtline = {0};

void
init(void)
{
	char *t;
	unsigned int i;

	/* read some control files */
	if (read_controls(ctrls) == -1)
		strerr_die2x(100, FATAL, "unable to read controls");

	sender = env_get("SENDER");
	if (!sender) strerr_die2x(100, FATAL, "SENDER not set");
	local = env_get("LOCAL");
	if (!local) strerr_die2x(100, FATAL, "LOCAL not set");
	host = env_get("HOST");
	if (!host) strerr_die2x(100, FATAL, "HOST not set");
	dname = env_get(ENV_GROUP);
	if (!dname) strerr_die2x(100, FATAL, "QLDAPGROUP not set");

	
	t = env_get("EXT");
	if (t != 0 && *t != '\0') {
		if (!stralloc_copyb(&base, local,
			    str_len(local) - str_len(t) - 1))
			temp_nomem();
		ext = t;
		ext += str_chr(ext, '-');
		if (!stralloc_copyb(&action, t, ext - t)) temp_nomem();
		if (!stralloc_0(&action)) temp_nomem();
		if (*ext) ++ext;
	} else {
		if (!stralloc_copys(&base, local)) temp_nomem();
		ext = 0;
	}
	if (!stralloc_copys(&dtline, "Delivered-To: ")) temp_nomem();
	if (!stralloc_cat(&dtline, &base)) temp_nomem();
	if (!stralloc_cats(&dtline, "@")) temp_nomem();
	if (!stralloc_cats(&dtline, host)) temp_nomem();
	for (i = 0; i < dtline.len; ++i)
		if (dtline.s[i] == '\n')
			dtline.s[i] = '_';
	if (!stralloc_cats(&dtline,"\n")) temp_nomem();
}

char buf[4096];
stralloc line = {0};

void
bouncefx(void)
{
	substdio	ss;
	int		match;
	
	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &line, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (line.len <= 1) break;
		if (line.len == dtline.len)
			if (byte_equal(line.s, line.len, dtline.s))
				strerr_die2x(100, FATAL,
				    "this message is looping: "
				    "it already has my Delivered-To line. "
				    "(#5.4.6)");
	}
}

void
reset_sender(void)
{
	substdio	 ss;
	char		*s;
	int		 match;
	unsigned int	 i;

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &line, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (line.len <= 1) break;
		if (case_startb(line.s, line.len, "Return-Path:")) {
			i = byte_chr(line.s, line.len, '<');
			if (i >= line.len)
				continue;
			s = line.s + i + 1;
			i = byte_rchr(line.s, line.len, '>');
			if (i >= line.len)
				continue;
			line.s[i] = '\0';
			if (!env_put2("SENDER",s)) temp_nomem();
			break;
		}
	}
	/* reget sender as it was possibly overwritten */
	sender = env_get("SENDER");
	if (!sender) strerr_die2x(100, FATAL, "SENDER not set");
}


char strnum1[FMT_ULONG];
char strnum2[FMT_ULONG];

void
blast(stralloc *r, int flagb)
{
	struct qmail qqt;
	substdio ss;
	char *s, *smax;
	const char *qqx;
	unsigned long qp;
	datetime_sec when;
	int match;

	if (r->s == (char *)0 || r->len == 0)
		strerr_die2x(100, FATAL, "no recipients found in this group.");

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));

	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	/* mail header */
	qmail_put(&qqt, dtline.s, dtline.len);
	qmail_puts(&qqt,"Precedence: bulk\n");
	do {
		if (getln(&ss, &line, &match, '\n') != 0) {
			qmail_fail(&qqt);
			break;
		}
		qmail_put(&qqt, line.s, line.len);
	} while (match);

	if (flagb && bounceadmin.s && bounceadmin.len) {
		if (!stralloc_copy(&line,&base)) temp_nomem();
		if (!stralloc_cats(&line,"-return-@")) temp_nomem();
		if (!stralloc_cats(&line,host)) temp_nomem();
		if (!stralloc_cats(&line,"-@[]")) temp_nomem();
		if (!stralloc_0(&line)) temp_nomem();
		qmail_from(&qqt, line.s);
	} else
		/* if no bounce admin specified forward with sender address */
		qmail_from(&qqt, sender);

	for (s = r->s, smax = r->s + r->len; s < smax; s += str_len(s) + 1)
		qmail_to(&qqt,s);
	qqx = qmail_close(&qqt);
	if (*qqx)
		strerr_die3x(*qqx == 'D' ? 100 : 111,
		    "Unable to blast message: ", qqx + 1, ".");
	when = now();
	strnum1[fmt_ulong(strnum1, (unsigned long) when)] = 0;
	strnum2[fmt_ulong(strnum2, qp)] = 0;
	trydelete();
	strerr_die5x(0, "qmail-group: ok ", strnum1, " qp ", strnum2, ".");
}

stralloc fname = {0};
char sbuf[1024];

void
reopen(void)
{
	int fd;

	if (!(fname.s && fname.len > 1))
		return;
	if (!stralloc_0(&fname)) temp_nomem();
	fd = open_read(fname.s);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "Unable to reopen old message: ");
	if (fd_move(0,fd) == -1) 
		strerr_die2sys(111, FATAL,
		    "Unable to reopen old message: fd_move: ");
	reset_sender();
}

void
trydelete(void)
{
	if (fname.s && fname.len > 1)
		unlink(fname.s);
}

void
secretary(char *maildir, int flagcheck)
{
	const char **args;
	char *s, *smax;
	int child, wstat;
	unsigned int i, numargs;
	int pi[2];
	int r, j;

	if (!stralloc_copys(&fname, "")) temp_nomem();

	if (seek_begin(0) == -1) temp_rewind();

	numargs = 4 + 2 * nummoderators;
	
	args = (const char **) alloc(numargs * sizeof(char *));
	if (!args) temp_nomem();
	i = 0;
	args[i++] = "qmail-secretary";
	if (flagcheck == 1)
		args[i++] = "-Zc";
	else 
		args[i++] = "-ZC";
	for (s = moderators.s, smax = moderators.s + moderators.len;
	    s < smax; s += str_len(s) + 1) {
		args[i++] = "-m";
		args[i++] = s;
		if (i + 2 > numargs)
		       strerr_die2x(111, FATAL, "internal error.");	
	}
	args[i++] = maildir;
	args[i++] = 0;
	
	if (pipe(pi) == -1)
		strerr_die2sys(111, FATAL,
		    "Unable to run secretary: pipe: ");
	
	coe(pi[0]);
	switch(child = fork()) {
	case -1:
		temp_fork();
	case 0:
		if (fd_move(1,pi[1]) == -1) 
			strerr_die2sys(111, FATAL,
			    "Unable to run secretary: fd_move: ");
		sig_pipedefault();
		execvp(*args, (char **)args);
		strerr_die3x(111,"Unable to run secretary: ",
		    error_str(errno), ". (#4.3.0)");
	}
	close(pi[1]);
	alloc_free(args);
	
	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		strerr_die2x(111, FATAL, "Aack, child crashed.");
	switch(wait_exitcode(wstat)) {
	case 100:
	case 64: case 65: case 70:
	case 76: case 77: case 78: case 112:
		_exit(100);
	case 0: case 99:
		/* XXX a for(;;) loop would be great */
		r = subread(pi[0], sbuf, sizeof(sbuf));
		if (r == -1) /* read error on a readable pipe, be serious */
			strerr_die2sys(111, FATAL,
			    "Unable to read secretary result: ");
		if (r == 0)
			/* need to wait for confirmation */
			_exit(0);
		for (j = 0; j < r; j++) {
			if (j == 0) {
				if (sbuf[j] != 'K')
					strerr_die2x(111, FATAL,
					    "Strange secretary dialect");
				else
					continue;
			}
			if (!stralloc_append(&fname, &sbuf[j])) temp_nomem();
		}
		close(pi[0]);
		return;
	default: _exit(111);
	}
}

/************ LDAP FUNCTIONS AND HELPER FUNCTIONS *************/

stralloc ldapval = {0};
stralloc tmpval = {0};

static void getmoderators(qldap *);
static int unescape(char *, stralloc *, unsigned int *);
static void extract_addrs822(qldap *, const char *, stralloc *, unsigned int *);
static void extract_addrsdn(qldap *, qldap *, const char *, stralloc *,
    unsigned int *);
static void extract_addrsfilter(qldap *, qldap *, const char *, stralloc *,
    unsigned int *);
static int getentry(qldap *, char *);

static void
getmoderators(qldap *q)
{
	qldap *sq;
	int r;
	
	nummoderators = 0; sq = (qldap *)0;
	if (!stralloc_copys(&moderators, "")) { r = ERRNO; goto fail; }

	extract_addrs822(q, LDAP_GROUPMODERAT822,
	    &moderators, &nummoderators);
	
	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;
	
	extract_addrsdn(q, sq, LDAP_GROUPMODERATDN,
	    &moderators, &nummoderators);
	
	qldap_free(sq);
	return;
	
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die3x(111, FATAL, "expand group: moderators: ",
	    qldap_err_str(r));
	/* NOTREACHED */
}

void
explode(qldap *q)
{
	qldap *sq;
	int r;

	sq = 0;
	if (!stralloc_copys(&recips, "")) { r = ERRNO; goto fail; }
	extract_addrs822(q, LDAP_GROUPMEMBER822, &recips, 0);

	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	extract_addrsdn(q, sq, LDAP_GROUPMEMBERDN, &recips, 0);
	extract_addrsfilter(q, sq, LDAP_GROUPMEMBERFILTER, &recips, 0);
	
	qldap_free(sq);
	return;
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die3x(111, FATAL, "expand group: members: ", qldap_err_str(r));
	/* NOTREACHED */
}

stralloc founddn = {0};

void
subscribed(qldap *q, int flagS)
{
	qldap *sq;
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	sq = 0;
	if (!stralloc_copys(&recips, "")) { r = ERRNO; goto fail; }
	extract_addrs822(q, flagS ? LDAP_GROUPSENDER822 : LDAP_GROUPMEMBER822,
	    &recips, 0);
	
	for (s = recips.s, smax = recips.s + recips.len; s < smax;
	    s += str_len(s) + 1)
		if (!case_diffs(sender, s)) return;

	/* open a second connection and do some dn lookups */
	sq = qldap_new();
	if (sq == 0) temp_nomem();

	r = qldap_open(sq);
	if (r != OK) goto fail;
	r = qldap_bind(sq, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	r = getentry(sq, sender);
	if (r == NOSUCH) {
		qldap_free(sq);
		qldap_free(q);
		strerr_die2x(100, FATAL,
		    "You are not allowed to post to this list. (#5.7.2)");
	}
	if (r != OK) goto fail;
	
	r = qldap_get_dn(sq, &founddn);
	if (r != OK) goto fail;
	
	r = qldap_get_attr(q, flagS ? LDAP_GROUPSENDERDN : LDAP_GROUPMEMBERDN,
	    &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1)
		if (!case_diffs(s, founddn.s)) {
			qldap_free(sq);
			return;
		}

	r = qldap_get_attr(q,
	    flagS ? LDAP_GROUPSENDERFILTER : LDAP_GROUPMEMBERFILTER,
	    &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, s, attrs, founddn.s, SCOPE_BASE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		if (qldap_count(sq) < 1) continue;
		/* match found */
		qldap_free(sq);
		return;
	}
	qldap_free(sq);
	qldap_free(q);
	strerr_die2x(100, FATAL,
	    "You are not allowed to post to this list. (#5.7.2)");
fail:
	if (sq) qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "sender ", sender, " verification failed: ",
	    qldap_err_str(r));
	/* NOTREACHED */
}


qldap *
ldapgroup(char *dn, int *flagc, int *flags, int *flagS)
{
	qldap *q;
	const char *attrs[] = {
		LDAP_GROUPCONFIRM,
		LDAP_GROUPMEMONLY,
		LDAP_GROUPCONFRIMTEXT,
		LDAP_GROUPMODERATTEXT,
		LDAP_GROUPMODERATDN,
		LDAP_GROUPMODERAT822,
		LDAP_GROUPMEMBERDN,
		LDAP_GROUPMEMBER822,
		LDAP_GROUPMEMBERFILTER,
		LDAP_GROUPSENDERDN,
		LDAP_GROUPSENDER822,
		LDAP_GROUPSENDERFILTER,
		LDAP_GROUPBOUNCEADMIN,
		0 };
	int r;
		
	q = qldap_new();
	if (q == 0) temp_nomem();

	r = qldap_open(q);
	if (r != OK) goto fail;
	r = qldap_bind(q, grouplogin.s, grouppassword.s);
	if (r != OK) goto fail;

	r = qldap_filter(q, "objectclass=*", attrs, dn, SCOPE_BASE);
	if (r != OK) goto fail;
	r = qldap_count(q);
	if (r != 1) {
		/* TOOMANY should be impossible with SCOPE_BASE */
		r = r==0 ? NOSUCH : TOOMANY;
		goto fail;
	}
	r = qldap_first(q); /* and only */
	if (r != OK) goto fail;
	
	r = qldap_get_bool(q, LDAP_GROUPCONFIRM, flagc);
	if (r != OK && r != NOSUCH) goto fail;
	
	r = qldap_get_bool(q, LDAP_GROUPMEMONLY, flags);
	if (r != OK && r != NOSUCH) goto fail;
	
	r = qldap_get_attr(q, LDAP_GROUPCONFRIMTEXT, &ldapval, SINGLE_VALUE);
	switch (r) {
	case OK:
		if (!env_put2("CONFIRMMESS", ldapval.s)) {
			r = ERRNO;
			goto fail;
		}
		break;
	case NOSUCH:
		if (!env_unset("CONFIRMMESS")) {
			r = ERRNO;
			goto fail;
		}
		break;
	default:
		goto fail;
	}
	
	r = qldap_get_attr(q, LDAP_GROUPMODERATTEXT, &ldapval, SINGLE_VALUE);
	switch (r) {
	case OK:
		if (!env_put2("APPROVEMESS", ldapval.s)) {
			r = ERRNO;
			goto fail;
		}
		break;
	case NOSUCH:
		if (!env_unset("APPROVEMESS")) {
			r = ERRNO;
			goto fail;
		}
		break;
	default:
		goto fail;
	}

	r = qldap_get_attr(q, LDAP_GROUPBOUNCEADMIN, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &bounceadmin, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}


	getmoderators(q);
	
	if (*flags) {
		r = qldap_get_attr(q, LDAP_GROUPSENDERDN,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			return q;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
		r = qldap_get_attr(q, LDAP_GROUPSENDER822,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			return q;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
		r = qldap_get_attr(q, LDAP_GROUPSENDERFILTER,
		    &ldapval, MULTI_VALUE);
		switch (r) {
		case OK:
			*flagS = 1;
			return q;
		case NOSUCH:
			break;
		default:
			goto fail;
		}
	}

	return q;
fail:
	qldap_free(q);
	strerr_die3x(111, FATAL, "get ldap group entry: ", qldap_err_str(r));
	/* NOTREACHED */
	return 0;
}

static int
unescape(char *s, stralloc *t, unsigned int *count)
{
	do {
		if (s[0] == '\\' && s[1] == ':') s++;
		else if (s[0] == ':') {
			if (count) *count += 1;
			if (!stralloc_0(t)) return ERRNO;
			continue;
		}
		if (!stralloc_append(t, s)) return ERRNO;
	} while (*s++);
	if (count) *count += 1;
	return OK;
}

static void
extract_addrs822(qldap *q, const char *attr, stralloc *list,
    unsigned int *numlist)
{
	int r;

	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, list, numlist);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	return;
fail:
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}
	
static void
extract_addrsdn(qldap *q, qldap *sq, const char *attr,
    stralloc *list, unsigned int *numlist)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	if (!stralloc_copys(&tmpval, "")) { r = ERRNO; goto fail; }
	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, "objectclass=*", attrs, s, SCOPE_BASE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		r = qldap_count(sq);
		if (r > 1) {
			/* TOOMANY should be impossible with SCOPE_BASE */
			r = TOOMANY;
			goto fail;
		} else if (r <= 0)
			continue;
		r = qldap_first(sq); /* and only */
		if (r != OK) goto fail;
		/* get mail address */
		r = qldap_get_attr(sq, LDAP_MAIL, &ldapval, SINGLE_VALUE);
		switch (r) {
		case OK:
			if (!stralloc_cat(list, &ldapval)) {
				r = ERRNO;
				goto fail;
			}
			if (numlist) *numlist += 1;
			break;
		case NOSUCH:
			/* WTF! Ignore. */
			break;
		default:
			goto fail;
		}
		/* free stuff for next search */
		qldap_free_results(sq);
	}
	return;
	
fail:
	qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}

static void
extract_addrsfilter(qldap *q, qldap *sq, const char *attr,
    stralloc *list, unsigned int *numlist)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *s, *smax;
	int r;

	if (!stralloc_copys(&tmpval, "")) { r = ERRNO; goto fail; }
	r = qldap_get_attr(q, attr, &ldapval, MULTI_VALUE);
	switch (r) {
	case OK:
		r = unescape(ldapval.s, &tmpval, 0);
		if (r != OK) goto fail;
		break;
	case NOSUCH:
		break;
	default:
		goto fail;
	}

	for (s = tmpval.s, smax = tmpval.s + tmpval.len;
	    s < smax; s += str_len(s) + 1) {
		r = qldap_filter(sq, s, attrs, qldap_basedn(), SCOPE_SUBTREE);
		if (r == NOSUCH) continue;
		if (r != OK) goto fail;
		r = qldap_first(sq);
		if (r != OK && r != NOSUCH) goto fail;
		if (r == NOSUCH) {
			qldap_free_results(sq);
			continue;
		}
		do {
			/* get mail address */
			r = qldap_get_attr(sq, LDAP_MAIL, &ldapval,
			    SINGLE_VALUE);
			switch (r) {
			case OK:
				if (!stralloc_cat(list, &ldapval)) {
					r = ERRNO;
					goto fail;
				}
				if (numlist) *numlist += 1;
				break;
			case NOSUCH:
				/* WTF! Ignore. */
				break;
			default:
				goto fail;
			}
			r = qldap_next(sq);
		} while (r == OK);
		if (r != NOSUCH) goto fail;
		
		/* free stuff for next search */
		qldap_free_results(sq);
	}
	return;
	
fail:
	qldap_free(sq);
	qldap_free(q);
	strerr_die5x(111, FATAL, "expand group attr: ", attr, ": ",
	    qldap_err_str(r));
	/* NOTREACHED */
}

stralloc filter = {0};

static int
getentry(qldap *sq, char *mail)
{
	const char *attrs[] = {
		LDAP_MAIL,
		0 };
	char *f;
	int done, rv;

	done = 0;
	do {
		/* build the search string for the email address */
		f = filter_mail(mail, &done);
		if (f == (char *)0) return ERRNO;

		/* do the search for the email address */
		rv = qldap_lookup(sq, f, attrs);
		switch (rv) {
		case OK:
			return OK;
		case NOSUCH:
			break;
		default:
			return rv;
		}
	} while (!done);
	return NOSUCH;
}
