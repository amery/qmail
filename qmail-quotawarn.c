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
#include <dirent.h>
#include <unistd.h>

#include "auto_qmail.h"
#include "byte.h"
#include "case.h"
#include "control.h"
#include "date822fmt.h"
#include "datetime.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "getln.h"
#include "mailmagic.h"
#include "myctime.h"
#include "newfield.h"
#include "now.h"
#include "open.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "wait.h"
#include "lock.h"

/* global vars */
stralloc warning = {0};
stralloc me = {0};
stralloc to = {0};
stralloc from = {0};
stralloc subject = {0};
stralloc header = {0};
stralloc qwline = {0};
stralloc temp = {0};

#define FATAL "qmail-quotawarn: fatal: "
#define WARN  "qmail-quotawarn: warn: "

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory.");
}
void
temp_qmail(char *fn)
{
	strerr_die4sys(111, FATAL, "Unable to open ", fn, ": ");
}
void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message.");
}
void
temp_slowlock()
{
	strerr_die2x(111, FATAL, 
	    "File has been locked for 30 seconds straight. (#4.3.0)");
}

void check_maildir(void);
void write_maildir(void);
void check_mailfile(char* fn);
void write_mailfile(char* fn);

void
readcontrol(void)
{
	int	fddir;

	fddir = open_read(".");
	if (fddir == -1)
		strerr_die2sys(111, FATAL, "Unable to open cwd: ");
	if (chdir(auto_qmail) == -1)
		strerr_die4sys(111, FATAL, "Unable to switch to ",
		    auto_qmail, ": ");

	if (control_init() == -1)
		strerr_die2sys(111, FATAL, "Unable to read controls: ");
	if (control_readline(&me, "control/me") != 1)
		strerr_die2sys(111, FATAL, "Unable to read control/me: ");
	if (control_readrawfile(&warning, "control/quotawarning") == -1)
		strerr_die2sys(111, FATAL,
		    "Unable to read control/quotawarning: ");
	else if (warning.len == 0)
		_exit(0);
	
	if (fchdir(fddir) == -1)
		strerr_die2sys(111,FATAL,"unable to switch back to cwd: ");
	close(fddir);
}

int
main(int argc, char **argv) 
{
	char *s;
	char *fn;


	if(!argv[1] || argv[2]) 
		strerr_die1x(100,
		    "qmail-quotawarn: usage: qmail-quotawarn mailbox.");

	fn = argv[1];

	readcontrol();
	
	if (!env_init()) temp_nomem();
	if (!(s = env_get("USER")))
		strerr_die1x(100, "UESR environment not present.");  
	if (!stralloc_copys(&qwline, "Qmail-QuotaWarning: ")) temp_nomem();
	if (!stralloc_cats(&qwline, s)) temp_nomem();
	if (!stralloc_append(&qwline, "@")) temp_nomem();
	if (!(s = env_get("HOST")))
		strerr_die1x(100, "HOST environment not present.");  
	if (!stralloc_cats(&qwline, s)) temp_nomem();
	if (!stralloc_append(&qwline, "\n")) temp_nomem();

	if (fn[str_len(fn)-1] == '/') {
		if (chdir(fn) == -1)
			strerr_die3sys(111, "Unable to switch to ", fn, ": ");
		check_maildir();
		write_maildir();
	} else {
		check_mailfile(fn);
		write_mailfile(fn);
	}
	/* NOTREACHED */
	return 1;
}

static char timebuf[DATE822FMT];

struct mheader mheader[] = {
	{ "From:", 0, ALLOW, 0 },
	{ "To:", 0, FORCE, 0 },
	{ "Subject:", "QUOTA-WARNING!\n", ALLOW, 0 },
	{ "MIME-Version:", "1.0", FORCE, 0 },
	{ "Content-Type:", "text/plain; charset=\"iso-8859-1\"\n", ALLOW, 0 },
	{ "Content-Transfer-Encoding:", "8bit", ALLOW, 0 },
	{ "X-", 0, ALLOW, 0 },
	{ DEFAULT, 0, DENY, 0 },
	{ 0, 0, 0, 0 }
};

int
writemail(substdio *ssout, datetime_sec starttime)
{
	struct datetime dt;
	char *t;
	int offset;

	/* store default To: From: Subject: */
	if (! (t = env_get("RECIPIENT")))
		strerr_die2x(111, FATAL, "RECIPIENT not present");
	mheader[1].v = t;

	if (!stralloc_copys(&from, "Qmail-QUOTAGUARD <MAILER-DAEMON@"))
		temp_nomem();
	if (!stralloc_cat(&from, &me)) temp_nomem();
	if (!stralloc_cats(&from, ">\n")) temp_nomem();
	if (!stralloc_0(&from)) temp_nomem();
	mheader[0].v = from.s;
	
	
	offset = headermagic(&warning, &header, 0, mheader);
	if (offset == -1) {
		if (errno == error_nomem) temp_nomem();
		return 0;
	}

	/*
	 * start writing header, first set:
	 * Return-Path: Delivered-to: Qmail-QuotaWarning:
	 * Received: Message-ID: Date:
	 */
	if (substdio_puts(ssout, "Return-Path: <>\n") == -1) return 0;

	if (!(t = env_get("DTLINE")))
		strerr_die2x(111, FATAL, "DTLINE not present");
	if (substdio_puts(ssout, t) == -1) return 0;
	/* Qmail-QuotaWarning: line */
	if (substdio_put(ssout, qwline.s, qwline.len)) return 0;
	/* Received: line */
	if (substdio_puts(ssout,
		    "Received: (directly through the "
		    "qmail-quotawarning program);\n\t"))
		return 0;
	datetime_tai(&dt, starttime);
	if (substdio_put(ssout, timebuf, date822fmt(timebuf, &dt))) return 0;
	
	/* message-id and date line */
	if (!newfield_datemake(starttime)) temp_nomem();
	if (!newfield_msgidmake(me.s, me.len, starttime)) temp_nomem();
	if (substdio_put(ssout, newfield_msgid.s, newfield_msgid.len))
		return 0;
	if (substdio_put(ssout, newfield_date.s, newfield_date.len))
		return 0;
	
	
	/* To: From: and Subject: */
	if (substdio_put(ssout, header.s, header.len)) return 0;
	/* don't forget the single \n */
	if (substdio_puts(ssout, "\n")) return 0;
	/* the Warning */
	if (substdio_put(ssout, warning.s + offset, warning.len - offset))
		return 0;
	if (warning.s[warning.len-1] == '\n')
		if (substdio_bputs(ssout, "\n")) return 0;
	
	return 1;
}

void
check_maildir(void)
{
	char const *(dirs[2]);
	DIR *folder;
	struct dirent *entry;
	int i;
	unsigned int j;

	dirs[0]="new"; dirs[1]="cur"; 
	for (i=0; i<2; i++) {
		/* checking for old mail */
		if ((folder = opendir(dirs[i])) == 0)
			strerr_die3sys(111, "Unable to opendir ", dirs[i], ": ");
		while ((entry = readdir(folder)) != 0) {
			if (*entry->d_name == '.') continue;
			j = str_rchr(entry->d_name, '.');
			if (entry->d_name[j++] == '\0') continue;
			if (!str_diffn("QUOTA_WARNING", &entry->d_name[j], 13))
				_exit(0);
		}
		closedir(folder);
	}
}

char fntmptph[80 + FMT_ULONG * 2];
char fnnewtph[83 + FMT_ULONG * 3];
void tryunlinktmp(void) { unlink(fntmptph); }
void sigalrm(void)
{
	tryunlinktmp();
	strerr_die1x(111, "Timeout on quota-warning delivery.");
}

char buf[1024];

void
write_maildir(void)
{
	char *s;
	int loop;
	int pid;
	int fd;
	datetime_sec starttime;
	struct stat st;
	substdio ssout;

	sig_alarmcatch(sigalrm);

	pid = getpid();
	starttime = now();
	for (loop = 0;;++loop) {
		s = fntmptph;
		s += fmt_str(s, "tmp/");
		s += fmt_ulong(s, starttime); *s++ = '.';
		s += fmt_ulong(s, pid); *s++ = '.';
		s += fmt_str(s, "QUOTA_WARNING"); 
		*s++ = 0;
		if (stat(fntmptph, &st) == -1) if (errno == error_noent) break;
		/* really should never get to this point */
		if (loop == 2)
			strerr_die2sys(111, FATAL, "Could not stat tmp file: ");
		sleep(2);
	}
	str_copy(fnnewtph, fntmptph);
	byte_copy(fnnewtph, 3, "new");

	alarm(86400);
	fd = open_excl(fntmptph);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "Unable to open tmp file: ");

	substdio_fdbuf(&ssout, subwrite, fd, buf, sizeof(buf));
	if (writemail(&ssout, starttime) == 0) goto fail;
	if (substdio_flush(&ssout) == -1) goto fail;

	if (fsync(fd) == -1) goto fail;
	if (fstat(fd, &st) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	s = fnnewtph;
	while( *s ) s++;
	s += fmt_str(s, ",S=");
	s += fmt_ulong(s, (unsigned long) st.st_size);
	*s++ = 0;

	if (link(fntmptph, fnnewtph) == -1)
		/* if error_exist unlink and exit(0),
		 * strange things can happen */
		if ( errno != error_exist) goto fail;

	tryunlinktmp();
	_exit(0);

fail:
	strerr_warn2(FATAL, "Writing Quota-Warning to maildir failed: ",
	    &strerr_sys);
	tryunlinktmp();
	_exit(111);
}

void
check_mailfile(char* fn)
{
	int fd;
	int match;
	substdio ss;

	fd = open_read(fn);
	if (seek_begin(fd) == -1) temp_rewind();

	substdio_fdbuf(&ss, subread, fd, buf, sizeof(buf));
	do {
		if(getln(&ss, &temp, &match, '\n') != 0) {
			strerr_warn2(WARN, "Unable to read message: ",
			    &strerr_sys);
			break;
		}
		if (temp.len == qwline.len)
			if (!case_diffb(qwline.s, qwline.len, temp.s)) {
				/* quota warning already in mailbox */
				close(fd);
				_exit(0);
			}
	} while (match);
	/* no quota warning found */
	close(fd);
}

void
write_mailfile(char* fn)
{
	int fd;
	substdio ssout;
	seek_pos pos;
	int flaglocked;
	datetime_sec starttime;

	starttime = now();

	fd = open_append(fn);
	if (fd == -1)
		strerr_die4sys(111, FATAL, "Unable to open ", fn, ": ");

	sig_alarmcatch(temp_slowlock);
	alarm(30);
	flaglocked = (lock_ex(fd) != -1);
	alarm(0);
	sig_alarmdefault();

	seek_end(fd);
	pos = seek_cur(fd);

	substdio_fdbuf(&ssout, subwrite, fd, buf, sizeof(buf));
	if (substdio_puts(&ssout, "From MAILER-DAEMON ")) goto writeerrs;
	if (substdio_puts(&ssout, myctime(starttime))) goto writeerrs;
	if (writemail(&ssout, starttime) == 0) goto writeerrs;
	if (substdio_bputs(&ssout, "\n")) goto writeerrs;
	if (substdio_flush(&ssout)) goto writeerrs;
	if (fsync(fd) == -1) goto writeerrs;
	close(fd);
	_exit(0);

writeerrs:
	strerr_warn4(FATAL, "Unable to write ", fn, ": ", &strerr_sys);
	if (flaglocked) seek_trunc(fd, pos);
	close(fd);
	_exit(111);
}

