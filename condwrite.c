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
/* based on qmail-local.c and condredirect.c by D. J. Bernstein */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "auto_qmail.h"
#include "byte.h"
#include "env.h"
#include "error.h"
#include "fmt.h"
#include "getln.h"
#include "gfrom.h"
#include "lock.h"
#include "maildir++.h"
#include "now.h"
#include "open.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "subfd.h"
#include "substdio.h"
#include "wait.h"
#ifdef AUTOMAILDIRMAKE
#include "mailmaker.h"
#include "qldap-errno.h"
#endif

#define FATAL "condwrite: fatal: "

void temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory. (#4.3.0)");
}

void temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message. (#4.3.0)");
}

void temp_childcrashed(void)
{
	strerr_die2x(111, FATAL, "Aack, child crashed. (#4.3.0)");
}

void temp_fork(void)
{
	strerr_die4x(111, FATAL, "Unable to fork: ",
	    error_str(errno), ". (#4.3.0)");
}

void
temp_slowlock(void)
{
	strerr_die2x(111, FATAL,
	    "File has been locked for 30 seconds straight. (#4.3.0)");
}

char		 fntmptph[80 + FMT_ULONG * 2];
char		 fnnewtph[83 + FMT_ULONG * 3];

void
tryunlinktmp(void)
{
	unlink(fntmptph);
}

void
sigalrm(void)
{
	tryunlinktmp();
	_exit(3);
}

char		*quotastring;

stralloc	 dtline = {0};
stralloc	 rpline = {0};
stralloc	 ufline = {0};
stralloc	 messline = {0};

char		 buf[1024];
char		 outbuf[1024];
int		 msfd = -1; /* global filedescriptor to the quota file */

void
maildir_child(char *dir)
{
	substdio	 ss, ssout;
	struct stat	 st;
	unsigned long	 pid, tnow;
	char		 host[64];
	char		*s;
	int		 loop, fd;

	sig_alarmcatch(sigalrm);
	if (chdir(dir) == -1) {
		if (error_temp(errno))
			_exit(1);
		else
			_exit(2);
	}

	pid = getpid();
	host[0] = 0;
	gethostname(host, sizeof(host));
	for (loop = 0;;++loop) {
		tnow = now();
		s = fntmptph;
		s += fmt_str(s, "tmp/");
		s += fmt_ulong(s, tnow); *s++ = '.';
		s += fmt_ulong(s, pid); *s++ = '.';
		s += fmt_strn(s, host, sizeof(host)); *s++ = 0;
		if (stat(fntmptph, &st) == -1)
			if (errno == error_noent)
				break;
		/* really should never get to this point */
		if (loop == 2)
			_exit(1);
		sleep(2);
	}
	str_copy(fnnewtph, fntmptph);
	byte_copy(fnnewtph, 3, "new");

	alarm(86400);
	fd = open_excl(fntmptph);
	if (fd == -1)
		_exit(1);

	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	substdio_fdbuf(&ssout, subwrite, fd, outbuf, sizeof(outbuf));
	if (substdio_put(&ssout, rpline.s, rpline.len) == -1) goto fail;
	if (substdio_put(&ssout, dtline.s, dtline.len) == -1) goto fail;

	switch(substdio_copy(&ssout, &ss)) {
	case -2:
		tryunlinktmp();
		_exit(4);
	case -3:
		goto fail;
	}

	if (substdio_flush(&ssout) == -1) goto fail;
	if (fsync(fd) == -1) goto fail;
	if (fstat(fd, &st) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	s = fnnewtph;
	while(*s) s++;
	s += fmt_str(s,",S=");
	s += fmt_ulong(s,(unsigned long)st.st_size);
	*s++ = 0;

	if(quotastring && *quotastring) {
		/* finally update the quota file "maildirsize" */
		quota_add(msfd, (unsigned long)st.st_size, 1);
		close(msfd);
	}

	if (link(fntmptph, fnnewtph) == -1) goto fail;
	/* if it was error_exist, almost certainly successful; i hate NFS */
	tryunlinktmp();
	_exit(0);

fail:
	tryunlinktmp();
	_exit(1);
}

/* end child process */

/* quota handling warning and bounce */
void
quota_bounce(const char *type)
{
	strerr_die4x(100, FATAL, "The users ", type,
	    " is over the allowed quota (size). (#5.2.2)");
}

stralloc	qwapp = {0};

void
quota_warning(char *fn)
{
	char	*(args[3]);
	int	 child, wstat;

	if (!stralloc_copys(&qwapp, auto_qmail)) temp_nomem();
	if (!stralloc_cats(&qwapp, "/bin/qmail-quotawarn")) temp_nomem();
	if (!stralloc_0(&qwapp)) temp_nomem();

	if (seek_begin(0) == -1) temp_rewind();

	switch(child = fork()) {
	case -1:
		temp_fork();
	case 0:
		args[0] = qwapp.s; args[1] = fn; args[2] = 0;
		sig_pipedefault();
		execv(*args,args);
		_exit(2);
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		temp_childcrashed();
	switch(wait_exitcode(wstat)) {
	case 2:
		strerr_die6x(111, FATAL, "Unable to run quotawarn program: ",
		    qwapp.s, ": ",error_str(errno),". (#4.2.2)");
	case 111:
		_exit(111);
	case 0:
		break;
	default:
		_exit(100);
	}

}

/* end -- quota handling warning and bounce */

void
maildir_write(char *fn)
{
	struct stat	mailst;
	quota_t		q;
	unsigned long	mailsize;
	int		child, wstat, perc;

#ifdef AUTOMAILDIRMAKE
	switch (maildir_make(fn)) {
	case OK:
		break;
	case MAILDIR_CORRUPT:
		strerr_die4x(111, FATAL, "The maildir '", fn,
		    "' seems to be corrupted. (#4.2.1)");
	case ERRNO:
	default:
		strerr_die4x(111, FATAL, "Unable to create maildir '",
		    fn, "' (#4.3.0)");
	}
#endif

	if (quotastring && *quotastring) {
		if (fstat(0, &mailst) != 0)
			strerr_die4x(111, FATAL,
			    "Can not stat mail for quota: ",
			    error_str(errno), ". (#4.3.0)");
		mailsize = mailst.st_size;
		quota_get(&q, quotastring);
		if (quota_calc(fn, &msfd, &q) == -1) {
			/* second chance */
			sleep(3);
			if (quota_calc(fn, &msfd, &q) == -1) {
				strerr_die2x(111, FATAL,
				    "Temporary race condition while "
				    "calculating quota. (#4.3.0)");
			}
		}
		/* fd can be -1, quota_add/rm take care of that */

		if (quota_check(&q, mailsize, 1, &perc) != 0) { /* 0 if OK */
			if (quota_recalc(fn, &msfd, &q) == -1) {
				/* second chance */
				sleep(3);
				if (quota_recalc(fn, &msfd, &q) == -1)
					strerr_die2x(111, FATAL,
					    "Temporary race condition while "
					    "recalculating quota. (#4.3.0)");
			}
			if (quota_check(&q, mailsize, 1, &perc) != 0) {
				/* bounce mail but drop a warning first */
				quota_warning(fn);
				quota_bounce("mailfolder");
			}
		}
		/* fd can be -1, quota_add/rm take care of that */

		if (perc >= QUOTA_WARNING_LEVEL) 
			/* drop a warning when mailbox is around 80% full */
			quota_warning(fn);
	}

	/* end -- quota handling maildir */

	if (seek_begin(0) == -1) temp_rewind();

	switch(child = fork()) {
	case -1:
		temp_fork();
	case 0:
		maildir_child(fn);
		_exit(111);
	}

	if (msfd != -1)
		close(msfd);
	/* close the maildirsize fd in the parent */

	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		temp_childcrashed();
	switch(wait_exitcode(wstat))
	{
	case 0:
		/* we exit with 99 so no more deliveries are done */
		_exit(99);
	case 2:
		strerr_die2x(111, FATAL,
		    "Unable to chdir to maildir. (#4.2.1)");
	case 3:
		strerr_die2x(111, FATAL,
		    "Timeout on maildir delivery. (#4.3.0)");
	case 4:
		strerr_die2x(111, FATAL, "Unable to read message. (#4.3.0)");
	default:
		strerr_die2x(111, FATAL,
		    "Temporary error on maildir delivery. (#4.3.0)");
	}
}

void
mailfile(char *fn)
{
	substdio	ss, ssout;
	struct stat	filest, mailst;
	quota_t		q;
	seek_pos	pos;
	unsigned long	totalsize;
	int		fd, match, flaglocked;

	if(quotastring && *quotastring) {
		quota_get(&q, quotastring);
		if (stat(fn, &filest) == -1) {
		 	/* size of nonexisting mailfile */
			filest.st_size = 0;
			if ( errno != error_noent)
				strerr_die6x(111, FATAL, "Unable to quota ", fn,
				    ": ",error_str(errno), ". (#4.3.0)");
		}
		if (fstat(0, &mailst) != 0)
			strerr_die4x(111, FATAL, "Unable to quota mail: ",
			    error_str(errno), ". (#4.3.0)");

		totalsize = (unsigned long)filest.st_size +
		    (unsigned long)mailst.st_size;
		if (totalsize * 100 / q.quota_size >= QUOTA_WARNING_LEVEL)
			/* drop a warning when mailbox is around 80% full */
			quota_warning(fn);
		if (totalsize > q.quota_size)
			quota_bounce("mailbox");
	}

	/* end -- quota handling mbox */

	if (seek_begin(0) == -1) temp_rewind();

	fd = open_append(fn);
	if (fd == -1)
		strerr_die6x(111, FATAL, "Unable to open ",fn,": ",
		    error_str(errno),". (#4.2.1)");

	sig_alarmcatch(temp_slowlock);
	alarm(30);
	flaglocked = (lock_ex(fd) != -1);
	alarm(0);
	sig_alarmdefault();

	seek_end(fd);
	pos = seek_cur(fd);

	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	substdio_fdbuf(&ssout, subwrite, fd, outbuf, sizeof(outbuf));
	if (substdio_put(&ssout, ufline.s, ufline.len)) goto writeerrs;
	if (substdio_put(&ssout, rpline.s, rpline.len)) goto writeerrs;
	if (substdio_put(&ssout, dtline.s, dtline.len)) goto writeerrs;

	for (;;) {
		if (getln(&ss, &messline, &match, '\n') != 0) {
			strerr_warn4(FATAL, "Unable to read message: ",
			    error_str(errno),". (#4.3.0)",0);
			if (flaglocked)
				seek_trunc(fd, pos);
			close(fd);
			_exit(111);
		}
		if (!match && !messline.len) break;
		if (gfrom(messline.s, messline.len))
			if (substdio_bput(&ssout, ">", 1)) goto writeerrs;
		if (substdio_bput(&ssout, messline.s, messline.len))
			goto writeerrs;
		if (!match) {
			if (substdio_bputs(&ssout, "\n")) goto writeerrs;
			break;
		}
	}
	if (substdio_bputs(&ssout, "\n")) goto writeerrs;
	if (substdio_flush(&ssout)) goto writeerrs;
	if (fsync(fd) == -1) goto writeerrs;
	close(fd);
	_exit(99);

writeerrs:
	strerr_warn6(FATAL, "Unable to write ", fn, ": ",
	    error_str(errno), ". (#4.3.0)",0);
	if (flaglocked) seek_trunc(fd, pos);
	close(fd);
	_exit(111);
}

int main(int argc, char **argv)
{
	char	*s;
	int	 pid, wstat;

	if (!env_init()) temp_nomem();
	if (!argv[1] || !argv[2])
		strerr_die1x(100,"condwrite: usage: "
		    "condwrite {maildir/|mailfile} program [ arg ... ]");

	if ((s = env_get("RPLINE"))) { 
		if (!stralloc_copys(&rpline, s)) temp_nomem();
	} else
		strerr_die2x(100, FATAL, "RPLINE not present.");

	if ((s = env_get("DTLINE"))) {
		if (!stralloc_copys(&dtline, s)) temp_nomem();
	} else
		strerr_die2x(100, FATAL, "DTLINE not present.");

	if ((s = env_get("UFLINE"))) {
		if (!stralloc_copys(&ufline, s)) temp_nomem();
	} else
		strerr_die2x(100, FATAL, "UFLINE not present.");

	pid = fork();
	if (pid == -1)
		temp_fork();
	if (pid == 0) {
		execvp(argv[2],argv + 2);
		if (error_temp(errno)) _exit(111);
		_exit(100);
	}

	if (wait_pid(&wstat,pid) == -1)
		strerr_die2x(111,FATAL,"wait failed");
	if (wait_crashed(wstat))
		temp_childcrashed();

	switch(wait_exitcode(wstat)) {
	case 0:
		break;
	case 111:
		strerr_die2x(111,FATAL,"temporary child error");
	default:
		  _exit(0);
	}

	if (seek_begin(0) == -1)
		temp_rewind();
	sig_pipeignore();

	/* quota, dotmode and forwarding handling - part 1 */
	/* setting the quota */
	quotastring = env_get(ENV_QUOTA);
 
	if(argv[1][str_len(argv[1]) - 1] == '/')
		maildir_write(argv[1]);
	else
		mailfile(argv[1]);

	return (100);
}
