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
#include <stdio.h>
#include <unistd.h>

#include "base64.h"
#include "byte.h"
#include "case.h"
#include "control.h"
#include "digest_sha1.h"
#include "direntry.h"
#include "env.h"
#include "error.h"
#include "fd.h"
#include "fmt.h"
#include "getln.h"
#include "mailmagic.h"
#include "newfield.h"
#include "now.h"
#include "open.h"
#include "qmail.h"
#include "quote.h"
#include "readwrite.h"
#include "seek.h"
#include "sgetopt.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"
#include "wait.h"
#ifdef AUTOMAILDIRMAKE
#include "qldap-errno.h"
#include "mailmaker.h"
#endif

#define FATAL "qmail-secretary: fatal: "
#define WARN  "qmail-secretary: warn: "

const char *confirmmess = "Hi,\n\n\
I'm mailgroup secretary, an automated mail-handling program.\n\
I received a message from you addressed to %LIST%\n\
for which I'm responsible. The top of your message is shown below.\n\
\n\
I'm here to protect the address %LIST% from\n\
all anonymous messages and bulk mail messages.\n\
\n\
If you reply to this notice, you are acknowledging that your message\n\
identifies you and is not part of a bulk mailing.\n\
I won't look at the contents of your reply. A simple OK is fine.\n\
\n\
If you do not reply to this notice, your message will be dropped\n\
and the recipient will not receive it.\n\
\n\
I realize that this confirmation process is inconvenient. I'm sorry for\n\
the hassle.\n\
\n\
Sincerely,\n\
The mailgroup secretary program\n\
\n\
";

const char *approvemess = "Hi,\n\n\
I'm mailgroup secretary, an automated mail-handling program.\n\
I need an approval that the attached message is allowed to be sent\n\
to the %LIST% mailinglist.\n\
\n\
To approve a message you must reply to this message. I won't look at\n\
the contents of your reply. A simple OK is fine.\n\
\n\
To deny a message no action must be taken. The message will be rejected\n\
automaticaliy after a few days.\n\
\n\
Sincerely,\n\
The mailgroup secretary program\n\
\n\
";

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory.");
}
void
temp_qmail(const char *fn)
{
	strerr_die4sys(111, FATAL, "Unable to open ", fn, ": ");
}
void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message.");
}
void
temp_read(void)
{
	strerr_die2x(111, FATAL, "Unable to read message.");
}
void
temp_fork(void)
{
	strerr_die2sys(111, FATAL, "Unable to fork: ");
}
void
die_badaddr(void)
{
	strerr_die2x(100, FATAL,
	    "I do not accept messages at this address (#5.1.1)");
}
void usage(void)
{
	strerr_die1x(100,
	    "qmail-secretary: usage:\n    "
	    "qmail-secretary [ -Z ] [ -c | -C ] [[ -m addr ] ... ] "
	    "[ -M file ] maildir\n    "
	    "qmail-secretary -z ezmlmdir [ -c | -C ] [[ -m addr ] ... ] "
	    "[ -M file ]\n                    maildir [ ezmlm-send ... ]\n");
}

char *sender;
char *host;
char *local;

stralloc mailinglist = {0};
stralloc inhost = {0};
stralloc inlocal = {0};
stralloc outhost = {0};
stralloc outlocal = {0};
stralloc messline = {0};
stralloc moderators = {0};
stralloc hashid = {0};
stralloc action = {0};
stralloc dtline = {0};
stralloc rpline = {0};
stralloc confirmtext = {0};
stralloc approvetext = {0};
stralloc foo = {0};

int flagconfirm = 0;
int flagezmlm = 0;

void nullsender(void);
void qgroupinit(void);
void ezmlminit(char *);
void extractrcpt(stralloc *, stralloc *);
void getconf_line(stralloc *, const char *, const char *);
void getconf_file(stralloc *, const char *, const char *);
void getconf_text(stralloc *, const char *, const char *, const char *);
void blast(stralloc *, const char *, const char *, char **);
char *replyaddr(stralloc *, const char *);
char *fromaddr(const char *);
char *moderatoraddr(void);
void sendconfirm(stralloc *, int);
void sendmoderator(stralloc *, int);
int sendmail(struct qmail *, int, int, stralloc *, stralloc *, stralloc *);
void attachmail(struct qmail *, int, unsigned int);
void bouncefx(void);
void createhash(int, stralloc *);
char *createname(stralloc *, const char *, const char *, stralloc *);
void checkmessage(stralloc *, const char *, const char *);
void delmessage(stralloc *, const char *, const char *);
int mvmessage(stralloc *, stralloc *, const char *);
void savemessage(stralloc *, const char *, const char *);
void reset_sender(void);
void clean(const char *);

int
main(int argc, char **argv)
{
	char		*ezmlmdir;
	char		*maildir;
	char		*modfile;
	int		opt;
	unsigned int	i;
	
	sender = env_get("SENDER");
	if (!sender) strerr_die2x(100, FATAL, "SENDER not set");
	local = env_get("LOCAL");
	if (!local) strerr_die2x(100, FATAL, "LOCAL not set");
	host = env_get("HOST");
	if (!host) strerr_die2x(100, FATAL, "HOST not set");

	if (!stralloc_copys(&moderators, "")) temp_nomem();
	modfile = 0;
	ezmlmdir = 0;
	
	while((opt = getopt(argc,argv,"cCm:M:z:Z")) != opteof)
	switch (opt) {
	case 'c':
		flagconfirm = 1;
		break;
	case 'C':
		flagconfirm = 0;
		break;
	case 'm':
		if (!stralloc_cats(&moderators, optarg)) temp_nomem();
		if (!stralloc_0(&moderators)) temp_nomem();
		break;
	case 'M':
		modfile = optarg;
		break;
	case 'z':
		flagezmlm = 1;
		ezmlmdir = optarg;
		break;
	case 'Z':
		flagezmlm = 0;
		break;
	default:
		usage();
		/* NOTREACHED */
	}
	
	argc -= optind;
	argv += optind;
	if (!(maildir = *argv++)) usage();
	if (!flagezmlm && *argv) usage();
	if (flagezmlm && !*argv) usage();

	if (flagezmlm == 0)
		qgroupinit();
	else
		ezmlminit(ezmlmdir); /* does a chdir to ezmlm dir */

	if (modfile != 0) {
		getconf_file(&messline, modfile, ezmlmdir);
		if (!stralloc_cat(&moderators, &messline)) temp_nomem();
		if (!stralloc_copys(&messline, "")) temp_nomem();
	}
	
	if (!quote2(&foo,sender)) temp_nomem();
	if (!stralloc_copys(&rpline,"Return-Path: <")) temp_nomem();
	if (!stralloc_cat(&rpline,&foo)) temp_nomem();
	for (i = 0;i < rpline.len;++i)
		if (rpline.s[i] == '\n')
			rpline.s[i] = '_';
	if (!stralloc_cats(&rpline,">\n")) temp_nomem();

	if (!stralloc_copys(&dtline, "Delivered-To: secretary for "))
		temp_nomem();
	if (!stralloc_cat(&dtline, &outlocal)) temp_nomem();
	if (!stralloc_cats(&dtline, "@")) temp_nomem();
	if (!stralloc_cat(&dtline, &outhost)) temp_nomem();
	for (i = 0; i < dtline.len; ++i)
		if (dtline.s[i] == '\n')
			dtline.s[i] = '_';
	if (!stralloc_cats(&dtline,"\n")) temp_nomem();
	
	
	extractrcpt(&action, &hashid);
#ifdef AUTOMAILDIRMAKE
	switch (maildir_make(maildir)) {
	case OK:
		break;
	case MAILDIR_CORRUPT:
		strerr_die4x(111,FATAL, "The maildir '", maildir,
		    "' seems to be corrupted. (#4.2.1)");
	case ERRNO:
	default:
		strerr_die4x(111,FATAL, "Unable to create maildir '", maildir,
		    "' (#4.3.0)");
	}
#endif

	if (action.len == 0) {
		nullsender();
		bouncefx();
		if (flagconfirm == 1) {
			savemessage(&hashid, maildir, "new/");
			sendconfirm(&hashid, 0);
		} else {
			savemessage(&hashid, maildir, "cur/");
			sendmoderator(&hashid, 0);
		}
		clean(maildir);
		_exit(99);
	} else if (case_startb(action.s, action.len, "approve")) {
		nullsender();
		bouncefx();
		if (hashid.len == 0)
			strerr_die2x(100, FATAL, "Approve message without id.");
		checkmessage(&hashid, maildir, "cur/");
		blast(&hashid, maildir, "cur/", argv);
		clean(maildir);
		_exit(99);
	} else if (case_startb(action.s, action.len, "confirm")) {
		nullsender();
		bouncefx();
		if (hashid.len == 0)
			strerr_die2x(100, FATAL, "Confirm message without id.");
		checkmessage(&hashid, maildir, "new/");
		if (moderators.len == 0)
			blast(&hashid, maildir, "new/", argv);
		else
			sendmoderator(&hashid,
			    mvmessage(&hashid, &hashid, maildir));
		clean(maildir);
		_exit(99);
	} else if (case_startb(action.s, action.len, "reject")) {
		delmessage(&hashid, maildir, "new/");
		clean(maildir);
		strerr_die2x(99, WARN, "confirmation to sender bounced.");
	} else if (case_startb(action.s, action.len, "bounce")) {
		clean(maildir);
		strerr_die2x(99, WARN, "message to moderator bounced.");
	} else if (case_startb(action.s, action.len, "moderators")) {
		clean(maildir);
		die_badaddr();
	}
	/* unknown action, pass mail to the next tool */
	clean(maildir);
	return 0;
}

void
nullsender(void)
{
	if (!*sender)
		strerr_die2x(100, FATAL,
		    "I don't reply to bounce messages. (#5.7.2)");
	if (!sender[str_chr(sender,'@')])
		strerr_die2x(100, FATAL,
		    "I don't reply to senders without host names."
		    " (#5.7.2)");
	if (str_diff(sender,"#@[]") == 0)
		strerr_die2x(100, FATAL,
		    "I don't reply to bounce messages. (#5.7.2)");
}

void
qgroupinit(void)
{
	char *t;

	/*
	 * following vars need to be set:
	 * inhost and outhost will be set to $HOST
	 * inlocal and outlocal will set to the base address of the group
	 * in other words: $LOCAL[0]..$LOCAL[strlen($LOCAL) - strlen($EXT) - 1]
	 * but only if EXT is non null else inlocal and outlocal are eq $LOCAL
	 */
	if (!stralloc_copys(&inhost, host)) temp_nomem();
	if (!stralloc_copys(&outhost, host)) temp_nomem();
	
	t = env_get("EXT");
	if (t != 0 && *t != '\0') {
		if (!stralloc_copyb(&inlocal, local,
			    str_len(local) - str_len(t) - 1))
			temp_nomem();
		if (!stralloc_copy(&outlocal, &inlocal)) temp_nomem();
	} else {
		if (!stralloc_copys(&inlocal, local)) temp_nomem();
		if (!stralloc_copys(&outlocal, local)) temp_nomem();
	}
	if (!stralloc_copy(&mailinglist, &outlocal)) temp_nomem();
	if (!stralloc_append(&mailinglist, "@")) temp_nomem();
	if (!stralloc_cat(&mailinglist, &outhost)) temp_nomem();
	
	t = env_get("APPROVEMESS");
	if (t != 0) {
		if (!stralloc_copys(&approvetext, t)) temp_nomem();
	} else {
		if (!stralloc_copys(&approvetext, approvemess)) temp_nomem();
	}
	t = env_get("CONFIRMMESS");
	if (t != 0) {
		if (!stralloc_copys(&confirmtext, t)) temp_nomem();
	} else {
		if (!stralloc_copys(&confirmtext, confirmmess)) temp_nomem();
	}
}

void
ezmlminit(char *dir)
{
	if (chdir(dir) == -1)
		strerr_die4sys(111,FATAL,"unable to switch to ",dir,": ");

	getconf_line(&mailinglist,"mailinglist", dir);
	getconf_line(&inhost,"inhost", dir);
	getconf_line(&inlocal,"inlocal", dir);
	getconf_line(&outhost,"outhost", dir);
	getconf_line(&outlocal,"outlocal", dir);

	getconf_text(&approvetext, "text/approve", dir, approvemess);
	getconf_text(&confirmtext, "text/confirm", dir, confirmmess);
}

void
extractrcpt(stralloc *a, stralloc *h)
{
	char		*s;
	unsigned int	i;

	if (!stralloc_copys(a, "")) temp_nomem();
	if (!stralloc_copys(h, "")) temp_nomem();

	if (inhost.len != str_len(host)) die_badaddr();
	if (case_diffb(inhost.s,inhost.len,host)) die_badaddr();
	if (inlocal.len > str_len(local)) die_badaddr();
	if (case_diffb(inlocal.s,inlocal.len,local)) die_badaddr();

	/*
	 * action is $LOCAL + inlocal.len + 1 but only if
	 * $LOCAL + inlocal.len == '-'
	 * and action.len is limited to str_chr(action.s, '-') - 1
	 * hash is $LOCAL + inlocal.len + 1 + action.len + 1
	 */
	s = local + inlocal.len;
	if (*s == '\0') return; /* no action, no hash */
	if (*s != '-') /* WTF, give up and let a other tool try */
		strerr_die2x(0, WARN, "mail address has bad extension.");
	s++;
	i = str_chr(s,'-');
	if (!stralloc_copyb(a, s, i)) temp_nomem();
	if (s[i] == '\0')
		return; /* just a action (e.g. moderators) */
	if (!stralloc_copys(h, s+i+1)) temp_nomem();
}

void
getconf_line(stralloc *sa, const char *fn, const char *dir)
{
	switch (control_readline(sa, fn)) {
	case 0:
		strerr_die5x(100, FATAL, dir, "/", fn, " does not exist");
	case 1:
		return;
	default:
		strerr_die6sys(111, FATAL, "unable to read ",
		    dir, "/", fn, ": ");
	}
}

void
getconf_file(stralloc *sa, const char *fn, const char *dir)
{
	switch (control_readfile(sa, fn, 0)) {
	case 0:
		strerr_die5x(100, FATAL, dir, "/", fn, " does not exist");
	case 1:
		return;
	default:
		strerr_die6sys(111, FATAL, "unable to read ",
		    dir, "/", fn, ": ");
	}
}

void
getconf_text(stralloc *sa, const char *fn, const char *dir, const char *def)
{
	switch (control_readrawfile(sa, fn)) {
	case 0:
		if (!stralloc_copys(sa, def)) temp_nomem();
	case 1:
		return;
	default:
		strerr_die6sys(111, FATAL, "unable to read ",
		    dir, "/", fn, ": ");
	}
}

char *
replyaddr(stralloc *h, const char *a)
{
	static stralloc addr;

	if (!stralloc_copy(&addr, &outlocal)) temp_nomem();
	if (!stralloc_cats(&addr, "-")) temp_nomem();
	if (!stralloc_cats(&addr, a)) temp_nomem();
	if (!stralloc_cats(&addr, "-")) temp_nomem();
	if (!stralloc_cat(&addr, h)) temp_nomem();
	if (!stralloc_cats(&addr, "@")) temp_nomem();
	if (!stralloc_cat(&addr, &outhost)) temp_nomem();
	if (!stralloc_0(&addr)) temp_nomem();

	return addr.s;
}

char *
fromaddr(const char *a)
{
	static stralloc from;

	if (!stralloc_copys(&from, "The mailgroup secretary <"))
		temp_nomem();
	if (!stralloc_cats(&from, a)) temp_nomem();
	if (!stralloc_cats(&from, ">\n")) temp_nomem();
	if (!stralloc_0(&from)) temp_nomem();
	
	return from.s;
}

char *
moderatoraddr(void)
{
	static stralloc modaddr;

	if (!stralloc_copys(&modaddr, "The moderators of "))
		temp_nomem();
	if (!stralloc_cat(&modaddr, &mailinglist)) temp_nomem();
	if (!stralloc_cats(&modaddr, " <")) temp_nomem();
	if (!stralloc_cat(&modaddr, &outlocal)) temp_nomem();
	if (!stralloc_cats(&modaddr, "-moderators@")) temp_nomem();
	if (!stralloc_cat(&modaddr, &outhost)) temp_nomem();
	if (!stralloc_cats(&modaddr, ">\n")) temp_nomem();
	if (!stralloc_0(&modaddr)) temp_nomem();
	
	return modaddr.s;
}

struct mheader mheader[] = {
	{ "To:", 0, FORCE, 0 },
	{ "From:", 0, FORCE, 0 }, /* envelope sender is fixed */
	{ "Subject:", 0, ALLOW, 0 },
//	{ "Reply-To:", 0, FORCE, 0 }, /* controversial RFC2076 */
	{ "MIME-Version:", "1.0", FORCE, 0 },
	{ "Content-Type:", 0, FORCE, 0 },
	{ "Content-Transfer-Encoding:", 0, FORCE, 0 },
	{ "X-Mailer:", "qmail-secretary (by qmail-ldap)", FORCE, 0 },
	{ "Precedence:", "junk", FORCE, 0 },
	{ "X-", 0, ALLOW, 0 },
	{ DEFAULT, 0, DENY, 0 },
	{ 0, 0, 0, 0 }
};

stralloc header = {0};
char strnum[FMT_ULONG];

void
sendconfirm(stralloc *hash, int fd)
{
	struct qmail qqt;
	const char *qqx;
	unsigned long qp;
	int r;
	
	mheader[0].v = sender;
	mheader[1].v = fromaddr(replyaddr(hash, "confirm"));
	mheader[2].v = "Message sender confirmation";

	r = headermagic(&confirmtext, &header, 0, mheader);
	if (r == -1)
		strerr_die2sys(111, FATAL, "Header magic failed: ");

	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	
	if (sendmail(&qqt, fd, 10*1024, &header, &confirmtext, hash) == -1)
		goto fail_nomem;
	
	qmail_from(&qqt, replyaddr(hash, "reject"));
	qmail_to(&qqt, sender);
	qqx = qmail_close(&qqt);
	if (!*qqx) {
		strnum[fmt_ulong(strnum, qp)] = 0;
		strerr_warn2("qmail-secretary: info: qp ", strnum, 0);
		return;
	}
	strerr_die4x(*qqx == 'D' ? 100 : 111, FATAL,
	    "Unable to send reply message: ", qqx + 1, ".");

fail_nomem:
	qmail_fail(&qqt);
	qmail_close(&qqt);
	temp_nomem();
}

void
sendmoderator(stralloc *hash, int fd)
{
	struct qmail qqt;
	char *s, *smax;
	const char *qqx;
	unsigned long qp;
	int r;
	
	mheader[0].v = moderatoraddr();
	mheader[1].v = fromaddr(replyaddr(hash, "approve"));
	mheader[2].v = "Moderation request";

	r = headermagic(&approvetext, &header, 0, mheader);
	if (r == -1)
		strerr_die2sys(111, FATAL, "Header magic failed: ");

	if (moderators.s == NULL || moderators.len == 0)
		strerr_die2x(100, FATAL,
		    "no moderators found but needed.");

	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);

	if (sendmail(&qqt, fd, 128*1024, &header, &approvetext, hash) == -1)
		goto fail_nomem;

	qmail_from(&qqt, replyaddr(hash, "bounce"));

	/* first check if the mail is comming from a moderator */
	for (s = moderators.s, smax = moderators.s + moderators.len; s < smax;
	    s += str_len(s) + 1) {
		if (!str_diff(sender, s)) {
			qmail_to(&qqt, s);
			break;
		}
	}
	/* not from a moderator so send to all moderators */
	if (s >= smax)
		for (s = moderators.s, smax = moderators.s + moderators.len;
		    s < smax; s += str_len(s) + 1) {
			qmail_to(&qqt, s);
		}

	qqx = qmail_close(&qqt);
	if (!*qqx) {
		strnum[fmt_ulong(strnum,qmail_qp(&qqt))] = 0;
		strerr_warn2("qmail-secretary: info: qp ", strnum, 0);
		return;
	}
	strerr_die4x(*qqx == 'D' ? 100 : 111, FATAL,
	    "Unable to send approve message: ", qqx + 1, ".");

fail_nomem:
	qmail_fail(&qqt);
	qmail_close(&qqt);
	temp_nomem();
}

struct mheader cheader[] = {
	{ "Content-Type:", "text/plain; charset=\"iso-8859-1\"\n", ALLOW, 0 },
	{ "Content-Transfer-Encoding:", "8bit", ALLOW, 0 },
	{ DEFAULT, 0, DENY, 0 },
	{ 0, 0, 0, 0 }
};

int
sendmail(struct qmail *qq, int fd, int maxsize,
    stralloc *head, stralloc *message, stralloc *hash)
{
	datetime_sec starttime;
	int offset;
	unsigned int len, i, j;
	
	/* mail header */
	qmail_put(qq, dtline.s, dtline.len);
	/* XXX Date: qmail uses GMT based dates which is sometimes confusing */
	/* message-id and date line */
	starttime = now();
	if (!newfield_datemake(starttime)) return -1;
	if (!newfield_msgidmake(inhost.s, inhost.len, starttime)) return -1;
	qmail_put(qq, newfield_msgid.s, newfield_msgid.len);
	qmail_put(qq, newfield_date.s, newfield_date.len);

	if (flagezmlm) {
		qmail_puts(qq, "Mailing-List: ");
		qmail_put(qq, mailinglist.s, mailinglist.len);
		qmail_puts(qq, "\n");
	}
	/* mime magic (multipart/mixed) header*/
	mimemagichead(head, hash);
	
	/* write parsed header */
	qmail_put(qq, head->s, head->len);

	/* end of header marker */
	qmail_puts(qq, "\n");

	/* mime magic (first attachement secretary text)*/
	qmail_puts(qq, mimemagic());
	qmail_puts(qq, "\n");
	
	offset = headermagic(message, head, 0, cheader);
	if (offset == -1) return -1;
	qmail_put(qq, head->s, head->len);
	qmail_puts(qq, "\n");
	
	/* body, expand %LIST% to list name. */
	len = message->len;
	for (i = offset; i < len; i += j) {
		j = byte_chr(message->s + i, len - i, '%');
		qmail_put(qq, message->s + i, j);
		if (*(message->s + i + j) == '%') {
			if (case_startb(message->s + i + j,
				    len - i -j, "%LIST%")) {
				qmail_put(qq, outlocal.s, outlocal.len);
				qmail_puts(qq, "@");
				qmail_put(qq, outhost.s, outhost.len);
				i += 6;
			} else {
				qmail_put(qq, message->s + i + j, 1);
				j++;
			}
		}
	}
	/* add a empty newline, just to be sure */
	qmail_puts(qq, "\n");

	/* mime magic (second attachement user message) */
	qmail_puts(qq, mimemagic());
	qmail_puts(qq, "\n");
	qmail_puts(qq, "Content-Type: message/rfc822\n\n");
	
	/* attach ~10kB of message */
	attachmail(qq, fd, maxsize);

	/* mime magic end */
	qmail_puts(qq, mimemagic());
	qmail_puts(qq, "--\n\n");
	return 0;
}

char buf[4096];

void
attachmail(struct qmail *qq, int fd, unsigned int maxsize)
{
	substdio	ss;
	int		match;
	
	if (seek_begin(fd) == -1) {
		qmail_fail(qq);
		qmail_close(qq);
		temp_rewind();
	}
	substdio_fdbuf(&ss, subread, fd, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &messline, &match, '\n') != 0) {
			qmail_fail(qq);
			qmail_close(qq);
			temp_read();
		}
		if (!match) break;
		if (messline.len > maxsize && messline.len > 100)
			messline.len = maxsize;
		qmail_put(qq, messline.s, messline.len);
		maxsize -= messline.len;
		if (maxsize <= 0) {
			qmail_puts(qq,"\n\n--- End of message stripped.\n");
			break;
		}
	}
	qmail_puts(qq, "\n");
}

void
bouncefx(void)
{
	substdio	ss;
	int		match;
	unsigned int	l;

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &messline, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (messline.len <= 1) break;
		if (case_startb(messline.s, messline.len, "mailing-list:"))
			strerr_die2x(100, FATAL,
			    "incoming message has Mailing-List. (#5.7.2)");
		if (case_startb(messline.s, messline.len, "precedence:")) {
			for (l = 11; l < messline.len; l++)
				if (messline.s[l] != ' ' &&
				    messline.s[l] != '\t')
					break;
			if (case_startb(messline.s + l, messline.len - l,
			    "junk") ||
			    case_startb(messline.s + l, messline.len - l,
			    "bulk") ||
			    case_startb(messline.s + l, messline.len - l,
			    "list"))
				strerr_die2x(100, FATAL,
				    "incoming message has bad precedence. "
				    "(#5.7.2)");
		}
		if (messline.len == dtline.len)
			if (byte_equal(messline.s, messline.len, dtline.s))
				strerr_die2x(100, FATAL,
				    "this message is looping: "
				    "it already has my Delivered-To line. "
				    "(#5.4.6)");
	}
}

unsigned char	sha1_hash[SHA1_LEN];

void
createhash(int fd, stralloc *hash)
{
	SHA1_CTX	ctx;
	substdio	ss;
	unsigned long	ul;
	int		match;
	
	if (!stralloc_copys(hash, "")) temp_nomem();
	SHA1Init(&ctx);
	/*
	 * XXX this is neither 64bit clean nor endian safe but
	 * I don't care. The hash is calculated only once and needs
	 * to include enough entropy to make it almost impossible to
	 * guess or bruteforce attack the hash.
	 */
	ul = (unsigned long) now();
	SHA1Update(&ctx, (unsigned char *)&ul, sizeof(unsigned long));
	ul = (unsigned long) getpid();
	SHA1Update(&ctx, (unsigned char *)&ul, sizeof(unsigned long));


	if (seek_begin(fd) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, fd, buf, sizeof(buf));
	for (;;)
	{
		if (getln(&ss, &messline, &match, '\n') != 0) temp_read();
		if (!match) break;
		SHA1Update(&ctx, messline.s, messline.len);
	}

	SHA1Final(sha1_hash, &ctx);
	if (hex_ntops(sha1_hash, sizeof(sha1_hash), hash) == -1)
		temp_nomem();
}

stralloc fname = {0};
stralloc nname = {0};

char *
createname(stralloc *sa, const char *maildir, const char *subdir, stralloc *h)
{
	if (!stralloc_copys(sa, maildir)) temp_nomem();
	if (sa->s[sa->len-1] != '/')
		if (!stralloc_append(sa, "/")) temp_nomem();
	if (!stralloc_cats(sa, subdir)) temp_nomem();
	if (sa->s[sa->len-1] != '/')
		if (!stralloc_append(sa, "/")) temp_nomem();
	if (!stralloc_cat(sa, h)) temp_nomem();
	if (!stralloc_0(sa)) temp_nomem();
	return sa->s;
}

void
checkmessage(stralloc *hash, const char *maildir, const char *subdir)
{
	struct	stat	st;
	char	*s;

	s = createname(&fname, maildir, subdir, hash);
	
	if (stat(s,&st) == -1) {
		if (errno == error_noent)
			strerr_die2x(99, WARN,
			    "Message no longer in repository.");
		strerr_die2sys(111, FATAL,
		    "Could not stat message: ");
	}
}

void
delmessage(stralloc *hash, const char *maildir, const char *subdir)
{
	struct	stat	st;
	char	*s;

	s = createname(&fname, maildir, subdir, hash);
	
	if (stat(s,&st) == -1) {
		if (errno == error_noent) return;
		strerr_die2sys(111, FATAL, "Could not stat message: ");
	}
	if (unlink(s) == -1)
		strerr_warn2(WARN, "Could not unlink message: ", &strerr_sys);
}

int
mvmessage(stralloc *hash, stralloc *newhash, const char *maildir)
{
	struct	stat	st;
	char	*s, *t;
	int	loop, fd;

	s = createname(&fname, maildir, "new/", hash);
	
	if (stat(s,&st) == -1) {
		if (errno == error_noent)
			strerr_die2x(99, WARN,
			    "Message no longer in repository.");
		strerr_die2sys(111, FATAL,
		    "Could not stat message: ");
	}
	for (loop = 0;; ++loop) {
		createhash(0, hash);
		t = createname(&nname, maildir, "cur/", hash);
		if (stat(t, &st) == -1 && errno == error_noent)
			break;
		/* really should never get to this point */
		if (loop == 2)
			strerr_die2sys(111, FATAL, "Could not stat new file: ");
		sleep(2);
	}	

	if (rename(s, t) == -1)
		strerr_die2sys(111, FATAL, "Could not move file: ");

	fd = open_read(t);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "Unable to open message: ");
	
	return fd;
}

char outbuf[4096];

void tryunlinktmp(void) { unlink(fname.s); }
void sigalrm(void)
{
	tryunlinktmp();
	strerr_die1x(111, "Timeout on maildir delivery.");
}

void
savemessage(stralloc *hash, const char *maildir, const char *subdir)
{
	struct	stat	st;
	substdio	ss, ssout;
	char		*s, *t;
	int		loop, fd;
	
	sig_alarmcatch(sigalrm);

	for (loop = 0;; ++loop) {
		createhash(0, hash);
		s = createname(&nname, maildir, subdir, hash);
		t = createname(&fname, maildir, "tmp/", hash);
		if (stat(s, &st) == -1 && errno == error_noent)
			if (stat(t, &st) == -1 && errno == error_noent)
				break;
		/* really should never get to this point */
		if (loop == 2)
			strerr_die2sys(111, FATAL, "Could not stat tmp file: ");
		sleep(2);
	}
	alarm(86400);
	fd = open_excl(t);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "Unable to open tmp file: ");

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	substdio_fdbuf(&ssout, subwrite, fd, outbuf, sizeof(outbuf));
	if (substdio_put(&ssout, rpline.s, rpline.len) == -1) goto fail;
	if (substdio_put(&ssout, dtline.s, dtline.len) == -1) goto fail;

	switch(substdio_copy(&ssout, &ss)) {
	case -2:
		strerr_warn2(FATAL, "Unable to read message: ",
		    &strerr_sys);
		tryunlinktmp();
		_exit(111);
	case -3:
		goto fail;
	}

	if (substdio_flush(&ssout) == -1) goto fail;
	if (fsync(fd) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	if (link(t, s) == -1) goto fail;
	/* if it was error_exist, almost certainly successful; i hate NFS */
	tryunlinktmp(); 
	sig_alarmdefault();
	return;

fail:
	strerr_warn2(FATAL, "Unable to store message: ",
	    &strerr_sys);
	tryunlinktmp();
	_exit(111);
}

void
blast(stralloc *hash, const char *maildir, const char *subdir, char **args)
{
	substdio ssout;
	char *s;
	int child, fd, wstat;

	s = createname(&nname, maildir, subdir, hash);

	if (flagezmlm) {
		switch (child = fork()) {
		case -1:
			temp_fork();
		case 0:
			fd = open_read(s);
			if (fd == -1)
				strerr_die2sys(111, FATAL,
				    "Unable to open message: ");
			if (fd_move(0,fd) == -1)
				strerr_die2sys(111, FATAL,
				    "Unable to move fd: ");
			reset_sender();
			if (seek_begin(0) == -1) temp_rewind();

			sig_pipedefault();
			execv(*args, args);
			strerr_die2sys(111, FATAL, "Unable to exec: ");
		}
		wait_pid(&wstat, child);
		if (wait_crashed(wstat))
			strerr_die2x(111, FATAL, "Aack, child crashed.");
		switch(wait_exitcode(wstat)) {
		case 0:
		case 99:
			if (unlink(s) == -1)
				strerr_warn2(WARN,
				    "Could not unlink message: ", &strerr_sys);
			return;
		case 100:
		case 64:
		case 65:
		case 70:
		case 76:
		case 77:
		case 78:
		case 112:
			_exit(100);
		default:
			_exit(111);
		}
	} else {
		substdio_fdbuf(&ssout, subwrite, 1, outbuf, sizeof(outbuf));
		if (substdio_puts(&ssout, "K") == -1) goto fail;
		if (substdio_puts(&ssout, s) == -1) goto fail;
		if (substdio_put(&ssout, "", 1) == -1) goto fail;
		if (substdio_flush(&ssout) == -1) goto fail;
		
		return;
fail:
		strerr_die2x(111, FATAL, "Unable to write to stdout: ");
	}
}

void
reset_sender(void)
{
	substdio	 ss;
	char		*s;
	unsigned int	 i;
	int		 match;

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &messline, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (messline.len <= 1) break;
		if (case_startb(messline.s, messline.len, "Return-Path:")) {
			i = byte_chr(messline.s, messline.len, '<');
			if (i >= messline.len)
				continue;
			s = messline.s + i + 1;
			i = byte_rchr(messline.s, messline.len, '>');
			if (i >= messline.len)
				continue;
			messline.s[i] = '\0';
			if (!env_put2("SENDER",s)) temp_nomem();
			break;
		}
	}
}

static void clean_child(void);

static void
clean_child(void)
{
	char const *(dirs[3]);
	struct stat st;
	DIR *folder;
	struct dirent *entry;
	datetime_sec t;
	unsigned int i;

	t = now();

	dirs[0]="new/"; dirs[1]="cur/"; dirs[2]="tmp/";
	for (i=0; i<3; i++) {
		/* checking for outdated mail */
		if ((folder = opendir(dirs[i])) == 0) {
			strerr_warn4(WARN, "Cleanup: Unable to opendir ",
			    dirs[i], ": ", &strerr_sys);
			_exit(2);
		}
		while ((entry = readdir(folder)) != 0) {
			if (*entry->d_name == '.') continue;
			if (!stralloc_copys(&fname, dirs[i])) _exit(1);
			if (!stralloc_cats(&fname, entry->d_name)) _exit(1);
			if (!stralloc_0(&fname)) _exit(1);
			/* remove files after a week */
			if (stat(fname.s,&st) == 0)
				if (t > st.st_mtime + 604800)
					unlink(fname.s);
		}
		closedir(folder);
	}
	_exit(0);
}

void
clean(const char *maildir)
{
	int child, wstat;

	switch (child = fork()) {
	case -1:
		strerr_warn2(WARN, "Cleanup: Unable to fork: ", &strerr_sys);
		return;
	case 0:
		if (chdir(maildir) == -1)
			_exit(3);
		clean_child();
	}

	wait_pid(&wstat, child);
	if (wait_crashed(wstat))
		strerr_warn2(WARN, "Cleanup: Aack, child crashed.", 0);
	switch(wait_exitcode(wstat)) {
	case 0:
		break;
	case 1:
		strerr_warn2(WARN, "Cleanup: Aack, child out of memory.", 0);
		break;
	case 2:
		break;
	case 3:
		strerr_warn4(WARN, "Cleanup: Unable to switch to ",
		    maildir, ": ", &strerr_sys);
		break;
	}
}

