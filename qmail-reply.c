/*
 * Copyright (c) 1999-2004 Claudio Jeker,
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
#include <unistd.h>
#include "base64.h"
#include "byte.h"
#include "case.h"
#include "control.h"
#include "constmap.h"
#include "digest_md5.h"
#include "direntry.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "getln.h"
#include "mailmagic.h"
#include "newfield.h"
#include "now.h"
#include "open.h"
#include "qmail.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "seek.h"
#include "sgetopt.h"
#include "sig.h"
#include "str.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"

#define FATAL "qmail-reply: fatal: "
#define WARN  "qmail-reply: warn: "

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory.");
}

void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message.");
}

void
temp_fork(void)
{
	strerr_die2sys(111, FATAL, "Unable to fork: ");
}

void
usage(void)
{
	strerr_die1x(100,
	    "qmail-reply: usage: qmail-reply [-f mailfile] [-j junkfile] "
	    "[maildir]");
}

stralloc replytext = {0};
stralloc hashed = {0};

void
hashreplytext(void)
{
	MD5_CTX ctx;
	unsigned char buffer[MD5_LEN];

	MD5Init(&ctx);
	MD5Update(&ctx, replytext.s, replytext.len);
	MD5Final(buffer,&ctx);

	if (hex_ntops(buffer, sizeof(buffer), &hashed) == -1) temp_nomem();
	if (!stralloc_0(&hashed) == -1) temp_nomem();
}

void
envmail(void)
{
	char *s;

	if ((s = env_get(ENV_REPLYTEXT))) {
		if (!stralloc_copys(&replytext, s)) temp_nomem();
	} else {
		strerr_die3x(100, FATAL, ENV_REPLYTEXT,
		    " not present.");
	}
	hashreplytext();
}

char buffer[1024];
stralloc line = {0};

void
readmail(char *file)
{
	substdio ss;
	int fd;
	int match;

	if (!stralloc_copys(&replytext, "")) temp_nomem();

	fd = open_read(file);
	if (fd == -1)
		strerr_die4sys(100, FATAL, "Unable to open '", file, "': ");
 
	substdio_fdbuf(&ss, subread, fd, buffer, sizeof(buffer));
	for (;;) {
		if (getln(&ss, &line, &match, '\n') == -1)
			strerr_die4sys(100, FATAL, "Unable to read '",
			    file, "': ");
		if (!match) {
			close(fd);
			return;
		}
		if (!stralloc_cat(&replytext, &line)) temp_nomem();
	}
	hashreplytext();
}

stralloc to={0};
stralloc from={0};
stralloc host={0};
stralloc dtline={0};

void
get_env(void)
{
	char *s;
	unsigned int i;

	if ((s = env_get("DTLINE")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment DTLINE not present.");
	if (!stralloc_copys(&dtline, s)) temp_nomem();

	if ((s = env_get("SENDER")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment SENDER not present.");
	if (!stralloc_copys(&to, s)) temp_nomem();

	if ((s = env_get("RECIPIENT")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment RECIPIENT not present.");
	if (!stralloc_copys(&from, s)) temp_nomem();

	i = byte_chr(from.s, from.len, '@');
	if (i == 0 || i >= from.len)
	  strerr_die2x(100, FATAL, "Bad RECIPIENT address.");

	if (!(s = env_get("HOST")))
		strerr_die2x(100, FATAL, "Environment HOST not present.");
	if (!stralloc_copys(&host, s)) temp_nomem();
}

stralloc junkfrom={0};
struct constmap mapjunk;

void
junkread(char *path)
{
	if (control_readfile(&junkfrom, path, 0) != 1)
		strerr_die4sys(100, FATAL, "Unable to read '", path, "': ");
}

int
junksender(char *addr, unsigned int len)
{
	unsigned int		at, dash, i;
	static const char	*(junkignore[]) = {
		/* don't reply to bots */
		"-request",
		"daemon",
		"-daemon",
		"uucp",
		"mailer-daemon",
		"mailer",
		/* don't bother admins */
		"postmaster",
		"root",
		/* from vacation(1) */
		"-relay",
		0 } ;
		/* TODO support for -return- dash extensions */
	
	for (i = 0; junkignore[i] != 0; i++) {
		if (!stralloc_cats(&junkfrom, junkignore[i])) temp_nomem();
		if (!stralloc_0(&junkfrom)) temp_nomem();
	}

	if (!constmap_init(&mapjunk, junkfrom.s, junkfrom.len, 0))
		strerr_die2sys(111, FATAL, "Constmap_init: ");
	
	at = byte_rchr(addr, len, '@');
	if (at >= len)
		strerr_die2x(111, FATAL, "Bad SENDER address.");

	/*
	   1. user@host
	   2. user
	   3. @host
	   4. -part
	 */
	if (constmap(&mapjunk, addr, len)) return 1;
	if (constmap(&mapjunk, addr, at)) return 1;
	if (constmap(&mapjunk, addr+at, len-at)) return 1;
	
	for (dash = 0; dash < at; dash++) {
		dash += byte_chr(addr+dash, at-dash, '-');
		if (constmap(&mapjunk, addr+dash, at-dash)) return 1;
	}
	return 0;
}	

datetime_sec
get_stamp(char const *hex)
{
	unsigned long t;
	unsigned char c;

	t = 0;
	while((c = *hex++)) {
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a')
			c -= ('a' - 10);
		else 
			c -= ('A' - 10);
		if (c > 15)
			break;
		t = (t<<4) + c;
	}
	
	return (datetime_sec) t;	
}

char *
stamp(datetime_sec tm)
{
	static char stampbuf[10];
	static const char* digit = "0123456789abcdef";
	char *s;
	unsigned long t;

	t = (unsigned long) tm;
	s = stampbuf;
	*s++ = ':';
	*s++ = digit[(t >> 28) & 0x0f];
	*s++ = digit[(t >> 24) & 0x0f];
	*s++ = digit[(t >> 20) & 0x0f];
	*s++ = digit[(t >> 16) & 0x0f];
	*s++ = digit[(t >> 12) & 0x0f];
	*s++ = digit[(t >>  8) & 0x0f];
	*s++ = digit[(t >>  4) & 0x0f];
	*s++ = digit[ t        & 0x0f];
	*s = '\0';
	return stampbuf;
}

stralloc rs = {0}; /* recent sender */
datetime_sec timeout;
#ifndef REPLY_TIMEOUT
#define REPLY_TIMEOUT 1209600 /* 2 weeks */
#endif
#define MAX_SIZE (128 * 1024) /* 128kB space for recent sender db */

int checkstamp(char *, unsigned int);

int
recent_lookup(char *buf, unsigned int len)
{
	char *s;
	datetime_sec last;
	unsigned int i, slen;
	
	switch (control_readfile(&rs,"qmail-reply.db",1)) {
		case 1:
			break;
		case 0:
			goto done;
		default:
			strerr_die2sys(111, FATAL,
			    "Read database file failed: ");
	}

	slen = rs.len; s = rs.s;
	if (!case_startb(s, slen, "QRDBv1:")) goto done;
	s += 7; slen -= 7;
	if (slen < hashed.len || case_diffb(s, hashed.len, hashed.s) != 0)
		return 0;
	s += hashed.len; slen -= hashed.len;

	for (i = 0; i < slen; i += str_len(s+i) + 1) {
		if (case_diffb(buf, len, s+i) == 0) {
			/* match found, look at timeval */
			i += len;
			if (s[i++] != ':') {
				strerr_warn2(WARN,
				    "Database file corrupted", 0);
				unlink("qmail-reply.db");
				stralloc_copys(&rs, "");
				return 0;
			}
			last = get_stamp(s+i);
			if (last + timeout < now()) goto done;
			else return 1;
		}
	}
done:
	return checkstamp(buf, len);
}

int
trylock(void)
{
	struct stat st;
	int fd;
	
retry:
	if ((fd = open_excl("qmail-reply.lock")) == -1) {
		if (errno == error_exist) {
			if (stat("qmail-reply.lock", &st) == -1) {
				strerr_warn2(WARN, "Unable to stat lock: ",
				    &strerr_sys);
				return -1;
			}
			/* ... should never get to this point */
			if (st.st_mtime + 900 < now()) {
				/* stale lock file */
				if (unlink("qmail-reply.lock") == -1) {
					strerr_warn2(WARN,
					    "Unable to unlink lock: ",
					    &strerr_sys);
					return -1;
				}
				goto retry;
			}
			return 0;
		}
		strerr_warn2(WARN, "Unable to get lock: ", &strerr_sys);
		return -1;
	}
	close(fd);
	return 1;
}

void
unlock(void)
{
	if (unlink("qmail-reply.lock") == -1)
		strerr_warn2(WARN, "Unable to unlock: ", &strerr_sys);
}

stralloc sfs = {0};
stralloc spath = {0};

int
checkstamp(char *buf, unsigned int len)
{
	struct stat st;
	
	if (!stralloc_copys(&spath, "tmp/@") ||
	    !stralloc_catb(&spath, buf, len) ||
	    !stralloc_0(&spath)) temp_nomem();
	if (stat(spath.s,&st) == -1) {
		if (errno == error_noent) return 0;
		strerr_warn4(WARN, "Can't stat stamp file: ",
		    spath.s, ": ", &strerr_sys);
		return 0;
	}
	if (st.st_mtime + timeout < now()) return 0;
	return 1;
}

void
addstamps(void)
{
	DIR *dir;
	direntry *d;
	struct stat st;

	if (!stralloc_copys(&sfs, "")) {
		strerr_warn2(WARN, "Out of memory.", 0);
		return;
	}
	dir = opendir("tmp");
	if (!dir) {
		strerr_warn2(WARN, "Unable to opendir ./tmp: ", &strerr_sys);
		return;
	}
	while ((d = readdir(dir))) {
		if (d->d_name[0] != '@') continue;
		/* this is a possible stamp file */
		if (d->d_name[str_chr(d->d_name+1, '@')+1] != '@') {
			strerr_warn3(WARN, "Strange stamp file: ",
			    d->d_name, 0);
			continue;
		}
		if (!stralloc_copys(&spath, "tmp/") ||
		    !stralloc_cats(&spath, d->d_name) ||
		    !stralloc_0(&spath)) break;
		if (stat(spath.s,&st) == -1) {
			strerr_warn4(WARN, "Can't stat stamp file: ",
			    d->d_name, ": ", &strerr_sys);
			continue;
		}
		if (!stralloc_cat(&sfs, &spath)) break; 
		if (!stralloc_cats(&rs, d->d_name+1) ||
		    !stralloc_cats(&rs, stamp(st.st_mtime)) ||
		    !stralloc_0(&rs)) break;
	}
	closedir(dir);
	if (d) strerr_warn2(WARN, "Out of memory.", 0);
}

void
deletestamps(void)
{
	unsigned int i;
	char *s;

	s = sfs.s;
	for(i = 0; i < sfs.len; i += str_len(s+i) + 1) {
		unlink(s + i);
	}
}

char rsoutbuf[SUBSTDIO_OUTSIZE];
char fntmptph[32 + 2*FMT_ULONG];

void
sigalrm(void)
{
	unlink(fntmptph);
	unlock();
	strerr_die2x(111, FATAL, "Timeout while writing db file");
}

void
recent_update(char *buf, unsigned int len)
{
	struct stat st;
	substdio ss;
	char *s, *t;
	datetime_sec tm, last;
	unsigned long pid;
	unsigned int slen, i, n;
	int fd, loop;

	addstamps();

	/* first limit database length to MAX_SIZE */
	s = rs.s; slen = rs.len;
	/* hop over possible header */
	if (case_startb(s, slen, "QRDBv1:")) {
		i = str_len(s);
		slen -= i;
		s += i;
	}
	for(; slen > MAX_SIZE; ) {
		i = str_len(s) + 1;
		slen -= i;
		s += i;
	}

	/* optain a temp file */
	pid = getpid();
	for (loop = 0;;++loop) {
		tm = now();
		t = fntmptph;
		t += fmt_str(t, "tmp/qmail-reply.");
		t += fmt_ulong(t, pid); *t++ = '.';
		t += fmt_ulong(t, tm); *t++ = 0;

		if (stat(fntmptph, &st) == -1) if (errno == error_noent) break;
		/* ... should never get to this point */
		if (loop == 2) {
			strerr_warn2(WARN, "Could not stat tmp file:",
			    &strerr_sys);
			return;
		}
		sleep(2);
	}

	sig_alarmcatch(sigalrm);
	alarm(600); /* give up after 10 min */
	fd = open_excl(fntmptph);
	if (fd == -1) {
		strerr_warn2(WARN, "Unable to open tmp file: ", &strerr_sys);
		return;
	}
	
	substdio_fdbuf(&ss, subwrite, fd, rsoutbuf, sizeof(rsoutbuf));
	
	if (substdio_puts(&ss, "QRDBv1:") == -1) goto fail;
	if (substdio_puts(&ss, hashed.s) == -1) goto fail;
	if (substdio_put(&ss, "\n", 1) == -1) goto fail;

	/* dump database */
	for (i = 0; i < slen; i += str_len(s+i) + 1) {
		n = byte_chr(s+i, slen, ':');
		if (n++ < slen) {
			last = get_stamp(s + i + n);
			if (last + timeout < tm) continue;
		} else goto fail; /* database corrupted */
		if (substdio_puts(&ss, s+i) == -1) goto fail;
		if (substdio_put(&ss, "\n", 1) == -1) goto fail;
	}
	if (substdio_flush(&ss) == -1) goto fail;
	if (fsync(fd) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	if (unlink("qmail-reply.db") == -1 && errno != error_noent) goto fail;
	if (link(fntmptph, "qmail-reply.db") == -1) goto fail;
	/* if it was error_exist, almost certainly successful; i hate NFS */

	unlink(fntmptph);
	deletestamps();
	sig_alarmdefault();
	return;

fail:
	strerr_warn2(WARN, "Database update failed: ", &strerr_sys);
	unlink(fntmptph);
	sig_alarmdefault();
	return;
}

void
touchstamp(char *buf, unsigned int len)
{
	int fd;

	if (!stralloc_copys(&sfs, "tmp/@")) temp_nomem();
	if (!stralloc_catb(&sfs, buf, len)) temp_nomem();
	if (!stralloc_0(&sfs)) temp_nomem();

	if ((fd = open_trunc(sfs.s)) == -1)
		strerr_warn4(WARN, "Unable to create stamp ",
		    sfs.s, ": ", &strerr_sys);
	close(fd);
}

int
recent(char *buf, unsigned int len, char *dir)
{
	if (dir == 0) return 0;

	if (chdir(dir) == -1) {
		strerr_warn4(WARN, "Unable to switch to ", dir, ": ",
		    &strerr_sys);
		return 0;
	}

	switch (trylock()) {
	case 0:
		if (recent_lookup(buf, len) == 1)
			return 1;
		/* touch stamp file */
		touchstamp(buf, len);
		return 0;
	case 1:
		if (recent_lookup(buf, len) == 1) {
			unlock();
			return 1;
		}
		touchstamp(buf, len);
		recent_update(buf, len);
		unlock();
		return 0;
	default:
		/* warning print in trylock() */
		return 0;
	}
}

unsigned int
getfield(char *s, unsigned int len)
{
	unsigned int l;

	l = len;
	for(;;) {
		if (l-- == 0) break; if (*s++ == ':') break;
		if (l-- == 0) break; if (*s++ == ':') break;
		if (l-- == 0) break; if (*s++ == ':') break;
		if (l-- == 0) break; if (*s++ == ':') break;
	}
	for(;;) {
		if (l == 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l == 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l == 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l == 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
	}
	return len - l;
}

#ifndef REPLY_SUBJ
#define REPLY_SUBJ "Your Mail"
#endif

stralloc subject = {0};

int
parseheader(/* TODO names for to/cc checking */ void)
{
	substdio ss;
	char *s;
	int match, subj_set;
	unsigned int len, i;

	subj_set = 0;
	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buffer, sizeof(buffer) );
	do {
		if(getln(&ss, &line, &match, '\n') != 0) {
			strerr_warn3(WARN, "Unable to read message: ",
			    error_str(errno), 0);
			break; /* something bad happend, but we ignore it */
		}
		if (line.len == 0) /* something is wrong, bad message */
			break;
		s = line.s; len = line.len;
		switch(*s) {
		case '\n': /* end of header */
			if (subj_set == 0)
				if (!stralloc_copys(&subject, REPLY_SUBJ))
					temp_nomem();
			return 0;
		case 'M':
		case 'm': /* Mailing-List: */
			if (case_startb(s, len, "Mailing-List:")) {
				return 1;
				/* don't reply to mailing-lists */
			}
			break;
		case 'P':
		case 'p': /* Precedence: */
			if (case_startb(s, len, "Precedence:")) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
				if (case_startb(s, len, "junk") ||
				    case_startb(s, len, "bulk") ||
				    case_startb(s, len, "list"))
					return 1;
			}
			break;
		case 'S':
		case 's': /* Subject: */
			if (case_startb(s, len, "Subject:")) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
				
				if (len > 1) {
					/* subject has to be more than
					   1 char (normaly a \n)
					 */
					if (!stralloc_copyb(&subject, s, len-1))
						temp_nomem();
					subj_set=1;
				}
			}
			break;
		case 'C':
		case 'c': /* Cc: */
		case 'T':
		case 't': /* To: */
			/*  TODO check if address is listed in To or Cc field */
#if 0
			if (case_diffb("To:"
				    sizeof("To:") - 1, s) == 0 ||
			    case_diffb("Cc:"
				    sizeof("Cc:") - 1, s) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
			}
#endif
			break;
		case 'X':
		case 'x': /* X-RBL: */
			if (case_startb(s, len, "X-RBL:")) {
				return 1;
				/* don't reply to messages tagged as spam */
			}
			if (case_startb(s, len, "X-Spam-Status: Yes")) {
				return 1;
				/* don't reply to messages tagged as spam */
			}
			break;
		case ' ':
		case '\t':
			/* TODO multiline header Precedence, Subject, To and Cc */
		default:
			break;
		}
	} while (match);
	strerr_warn2(WARN,
	    "Premature end of header. The message has no body.", 0);
	if ( subj_set == 0 )
		if (!stralloc_copys(&subject, REPLY_SUBJ)) temp_nomem();

	return 0;
}

stralloc header = {0};

#ifndef REPLY_CT
#define REPLY_CT "text/plain; charset=iso-8859-1\n"
#endif
#ifndef REPLY_CTE
#define REPLY_CTE "8bit\n"
#endif

struct mheader mheader[] = {
	{ "From:", 0, ALLOW, 0 }, /* envelope sender is fixed */
	{ "To:", 0, FORCE, 0 },
	{ "Subject:", "[Auto-Reply] %SUBJECT%\n", SUBJECT, 0 },
	{ "MIME-Version:", "1.0", FORCE, 0 },
	{ "Content-Type:", REPLY_CT, ALLOW, 0 },
	{ "Content-Transfer-Encoding:", REPLY_CTE, ALLOW, 0 },
	{ "X-Mailer:", "qmail-reply (by qmail-ldap)", FORCE, 0 },
	{ "Precedence:", "junk", FORCE, 0 },
	{ "X-", 0, ALLOW, 0 },
	{ DEFAULT, 0, DENY, 0 },
	{ 0, 0, 0, 0 }
};

void
sendmail(void)
{
	struct qmail qqt;
	const char *qqx;
	datetime_sec starttime;
	unsigned long qp;
	int offset;
	
	if (!stralloc_0(&from)) temp_nomem();
	if (!stralloc_0(&to)) temp_nomem();

	mheader[0].v = from.s;
	mheader[1].v = to.s;
	offset = headermagic(&replytext, &header, &subject, mheader);
	if (offset == -1)
		strerr_die2sys(111, FATAL, "Header magic failed: ");
	
	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	qmail_put(&qqt,dtline.s,dtline.len);
	
	/* XXX Date: qmail uses GMT based dates which is sometimes confusing */
	/* message-id and date line */
	starttime = now();
	if (!newfield_datemake(starttime)) goto fail_nomem;
	if (!newfield_msgidmake(host.s, host.len, starttime)) goto fail_nomem;
	qmail_put(&qqt, newfield_msgid.s, newfield_msgid.len);
	qmail_put(&qqt, newfield_date.s, newfield_date.len);

	/* write parsed header */
	qmail_put(&qqt, header.s, header.len);
	/* end of header marker */
	qmail_puts(&qqt, "\n");

	/* body */
	qmail_put(&qqt, replytext.s + offset, replytext.len - offset);
	/* add a empty newline, just to be sure */
	qmail_puts(&qqt, "\n");
	/* use <> as envelope sender as we are not interested in bounces */
	qmail_from(&qqt, "");
	qmail_to(&qqt, to.s);
	qqx = qmail_close(&qqt);
	if (!*qqx) return;
	strerr_die4x(*qqx == 'D' ? 100 : 111, FATAL,
	    "Unable to send reply message: ", qqx + 1, ".");

fail_nomem:
	qmail_fail(&qqt);
	qmail_close(&qqt);
	temp_nomem();
}

int
main(int argc, char **argv)
{
	char *maildir;
	int flagenv;
	int opt;

	if (!env_init()) temp_nomem();
	
	flagenv = 1;
	timeout = REPLY_TIMEOUT;

	while((opt = getopt(argc,argv,"f:j:")) != opteof)
		switch (opt) {
		case 'f':
			readmail(optarg);
			flagenv = 0;
			break;
		case 'j':
			junkread(optarg);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	
	/* if more arguments are used */
	argc -= optind;
	argv += optind;
	maildir = *argv;
	
	if (flagenv == 1)
		envmail();

	/* get environment RECIPIENT, SENDER and DTLINE */
	get_env();

	/* check if a reply is needed */
	if (junksender(to.s, to.len)) _exit(0);
	/* parse header, exit if a precedence or mailinglist field
	   has been found or the mail is not directly sent to us. */
	if (parseheader()) _exit(0);
	/* already sent a message recently? */
	if (maildir && (*maildir == '.' || *maildir == '/') &&
	    maildir[str_len(maildir)-1] == '/')
		if (recent(to.s, to.len, maildir)) _exit(0);

	sendmail();
	return 0;
}

