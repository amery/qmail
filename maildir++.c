/*
 * Copyright (c) 2000-2004 Claudio Jeker,
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
#include <fcntl.h>
#include <unistd.h>

#include "alloc.h"
#include "byte.h"
#include "direntry.h"
#include "error.h"
#include "fmt.h"
#include "getln.h"
#include "now.h"
#include "open.h"
#include "readwrite.h"
#include "scan.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"

#include "maildir++.h"

static void temp_nomem() { strerr_die1x(111,"Out of memory. (QUOTA #1.0.1)"); }

static int mailfolder(void);
int quota_parsesize(quota_t *, int *, char *, int);
static int quota_calcsize(quota_t *, int *, char *, int);
static int quota_writesize(quota_t *, int *, time_t);
static int check_maxtime(time_t);
static int get_file_size(char *, struct stat *);
static void calc_curnew(quota_t *, time_t *);
static int read5120(const char *, char *, int *);


static stralloc	path = {0};
static char writebuf[3*FMT_ULONG]; /* enough big to hold all needed data */
static char buf5120[5120]; /* buffer for maildirsize */

/* alarm handler */
static void
sigalrm()
{
	unlink(path.s); 
	strerr_die1x(111,"Timeout while writing maildirsize. (QUOTA #1.0.2)");
}

void
quota_add(int fd, unsigned long size, unsigned long count)
/* add size and count to the quota (maildirsize) */
{
	char num[FMT_ULONG];
	seek_pos pos;
	substdio ss;

	if (fd == -1) return;

	seek_end(fd);
	pos = seek_cur(fd); /* again savety */

	substdio_fdbuf(&ss,subwrite,fd,writebuf,sizeof(writebuf));

	/* create string of the form '1234 12\n' and add it to the quota */
	if (substdio_bput(&ss, num, fmt_ulong(num, size) ) == -1)
		goto addfail;
	if (substdio_bput(&ss, " ", 1) == -1)
		goto addfail;
	if (substdio_bput(&ss, num, fmt_ulong(num, count) ) == -1)
		goto addfail;
	if (substdio_bput(&ss, "\n", 1) == -1)
		goto addfail;
	if (substdio_flush(&ss) == -1)
		goto addfail; 
	if (fsync(fd) == -1)
		goto addfail; 

	return;

addfail:
	strerr_warn3("Unable to add file to quota: ", error_str(errno), 
			". (QUOTA #1.2.1)",0);
	seek_trunc(fd,pos); /* recover form error */
	return; /* ignore errors, perhaps the file was removed */
}

void
quota_rm(int fd, unsigned long size, unsigned long count)
/* remove size and count from the quota (maildirsize) *
 * both size and count are POSITVE integers           */
{
	char num[FMT_ULONG];
	seek_pos pos;
	substdio ss;

	if (fd == -1) return;

	seek_end(fd);
	pos = seek_cur(fd); /* again savety */

	substdio_fdbuf(&ss,subwrite,fd,writebuf,sizeof(writebuf));

	/* create string of the form '-1232 -12\n' and add it to the quota */
	if (substdio_bput(&ss, "-", 1) == -1)
		goto rmfail;
	if (substdio_bput(&ss, num, fmt_ulong(num, size)) == -1)
		goto rmfail;
	if (substdio_bput(&ss, " -", 2) == -1)
		goto rmfail;
	if (substdio_bput(&ss, num, fmt_ulong(num, count)) == -1)
		goto rmfail;
	if (substdio_bput(&ss, "\n", 1) == -1)
		goto rmfail;
	if (substdio_flush(&ss) == -1)
		goto rmfail; 
	if (fsync(fd) == -1)
		goto rmfail; 
	return;

rmfail:
	strerr_warn3("Unable to remove file from quota: ", error_str(errno), 
			". (QUOTA #1.3.1)",0);
	seek_trunc(fd,pos); /* recover form error */
	return; /* ignore errors, perhaps the file was removed */
}

int
quota_calc(const char *dir, int *fd, quota_t *q)
{
	int i = 0;
	int ret;
	
	if (! stralloc_copys(&path, dir)) temp_nomem();
	if (path.s[path.len-1] != '/')
		if (! stralloc_cats(&path, "/")) temp_nomem();

	while (mailfolder()) {
		if (! stralloc_cats(&path, "../")) temp_nomem();
		if (i++ > 1 ) strerr_die1x(111, 
				"Unable to calc quota: recursive "
				"maildir++ (QUOTA #1.1.1)");
	}
	
	if (! stralloc_cats(&path, "maildirsize")) temp_nomem();
	if (! stralloc_0(&path)) temp_nomem();
	
	*fd = read5120(path.s, buf5120, &i);

	if (*fd != -1) {
		ret = quota_parsesize(q, fd, buf5120, i);
	} else {
		ret = quota_calcsize(q, fd, buf5120, i);
	}
	return ret;
}

int
quota_recalc(const char *dir, int *fd, quota_t *q)
{
	int  i = 0;
	int  j;
	int  lines = 0;
	time_t tm;
	struct stat st;
	
	if (!stralloc_copys(&path, dir)) temp_nomem();
	if (path.s[path.len-1] != '/')
		if (!stralloc_cats(&path, "/")) temp_nomem();

	while (mailfolder()) {
		if (!stralloc_cats(&path, "../")) temp_nomem();
		if (i++ > 1 ) strerr_die1x(111, 
				"Unable to calc quota: recursive "
				"maildir++ (QUOTA #1.1.1)");
	}
	
	if (!stralloc_cats(&path, "maildirsize")) temp_nomem();
	if (!stralloc_0(&path)) temp_nomem();
	
	*fd = read5120(path.s, buf5120, &i);
	
	if (*fd != -1) {
		for (j = 0; j < i && lines <= 2 ; j++) {
			if (buf5120[j] == '\n') lines++;
		}
		if (lines <= 2) {
			if (fstat(*fd, &st) == -1) 
				strerr_die3x(111,
					"Unable to fstat maildirsize: ", 
					error_str(errno), " (QUOTA #1.5.1)");
			tm = now();
			if (tm < st.st_mtime + 900) {
				/*
				   parsed quota of quota_calc() is still valid.
				   It is important that the caller does not
				   clear the quota struct.
				 */
				/*
				   If this can not be granted quota_parsesize()
				   needs to be called here.
				 */
				return 0;
			}
		}
		/* need to recalculate the quota */
		close(*fd);
		*fd = -1;
		unlink(path.s);
	}
	
	return quota_calcsize(q, fd, buf5120, i);
}

int
quota_check(quota_t *q, unsigned long size, unsigned long count, int *perc)
{
	int sp , cp;
	
	if (q->quota_size == 0 && q->quota_count == 0) {
		/* no quota defined */
		if (perc) *perc = 0;
		return 0;
	}
		
	if (perc != (int *)0) {
		sp = q->quota_size != 0 ?
			(int)((q->size + size)*100.0/q->quota_size) :
			0;
		cp = q->quota_count != 0 ?
			(int)((q->count + count)*100.0/q->quota_count) :
			0;
		if (sp > cp)
			*perc = sp;
		else
			*perc = cp;
	}
	
	if (q->size + size > q->quota_size && q->quota_size != 0) {
		return -1;
	}

	if (q->count + count > q->quota_count && q->quota_count != 0) {
		return -1;
	}
	
	return 0;
}

void
quota_get(quota_t *q, const char *quota)
{
	unsigned long i;

	q->quota_size = 0;
	q->quota_count = 0;
	q->size = 0;
	q->count = 0;
	
	if (quota == (char *)0) return;

	while (*quota) {
		if (*quota < '0' || *quota > '9') {
			quota++;
			continue;
		}

		/* parse found number */
		quota += scan_ulong(quota, &i);

		switch (*quota) {
			case 'S':
				q->quota_size = i;
				break;
			case 'C':
				q->quota_count = i;
				break;
			default:
				/* ignore */
				break;
		}
	}
}

static int
mailfolder(void)
{
	unsigned int len;
	struct stat st;
	
	/* 
	 * check if we are in a maildir subfolder, normaly this is impossible
	 */
	
	len = path.len;
	if (!stralloc_cats(&path, "maildirfolder")) temp_nomem();
	if (!stralloc_0(&path)) temp_nomem();
	path.len = len; /* cut away what this function has added */

	if (stat(path.s, &st) == -1) { /* are we in a subdir ? */
		if (errno != error_noent) {
			strerr_die3x(111, "Unable to stat maildirfolder: ", 
					error_str(errno), " (QUOTA #1.4.1)");
		}
		return 0;
	} else {
		return 1;
	}
}

int
quota_parsesize(quota_t *q, int *fd, char *buf, int len)
{
	char *s;
	quota_t dummy;
	long fig, pn;
	int i;
	char c;
	
	for (i = 0; i < len; i++) {
		if (buf[i] == '\n') buf[i] = '\0';
	}
	
	quota_get(&dummy, buf);
	if (q->quota_size == 0 && q->quota_count == 0) {
		/* no quota defined */
		q->quota_size = dummy.quota_size;
		q->quota_count = dummy.quota_count;
	}

	if (q->quota_size != dummy.quota_size || 
		 q->quota_count != dummy.quota_count) {
		/* quota definition has changed, remove old maildirsize file
		 * and recalculate the quota */
		close(*fd); *fd = -1;
		unlink(path.s);
		return quota_calcsize(q, fd, buf, len);
	}
	
	q->size = 0; q->count = 0; /* just to be sure */
	s = buf;
	
	while (s - buf < len) {
		while (*s++) ; /* hop over the last line */
		
		pn = 1;
		while ((c = *s) < '0' || c > '9') {
			if (c == '\0') break;
			if (c == '-') pn = -1;
			s++; /* hop over spaces */
		}
		if (c == '\0') continue;
		
		/* first comes the size ... */
		if ((i = scan_ulong(s, &fig)) == 0) continue;
		s += i;
		q->size += (fig * pn);

		pn = 1;
		while ((c = *s) < '0' || c > '9') {
			if (c == '-') pn = -1;
			s++; /* hop over spaces */
		}

		/* ... then the file count */
		if ((i = scan_ulong(s, &fig)) == 0) continue;
		s += i;
		q->count += (fig * pn);
	}

	return 0;
}

static int
quota_calcsize(quota_t *q, int *fd, char *buf, int len)
{
	unsigned int plen;
	time_t tm;
	time_t maxtime;
	direntry *dp;
	DIR *dirp;
	
	if (q->quota_size == 0 && q->quota_count == 0) {
		/* no quota defined */
		return 0;
	}

	q->size = 0; q->count = 0; /* just to be sure */
	
	tm = now();
	maxtime = 0;

	/* first pop away 'maildirsize' in path */
	path.len -= 12; /* including the '\0' char */
	plen = path.len;
	
	if (!stralloc_0(&path)) temp_nomem();
	
	dirp = opendir(path.s);
	while (dirp && (dp = readdir(dirp)) != 0) {
		if (dp->d_name[0] == '.' &&
		    dp->d_name[1] != '\0' &&
		    dp->d_name[1] != '.'
#ifndef QUOTATRASH
		    && str_diff(".Trash", dp->d_name)
#endif
		   ) {
			
			path.len = plen;
			if (!stralloc_cats(&path, dp->d_name)) temp_nomem();
			calc_curnew(q, &maxtime);
			path.len = plen;
		}
	}
	if (dirp) closedir(dirp);
	
	path.len = plen;
	calc_curnew(q, &maxtime);
	path.len = plen;

	/* quota is calculated, now create the new maildirsize file */
	return quota_writesize(q, fd, maxtime);
}

static int
quota_writesize(quota_t *q, int *fd, time_t maxtime)
{
	int pid;
	int i;
	char *buf;
	char *s;
	char num[FMT_ULONG];
	time_t tm;
	struct stat st;
	substdio ss;

	/* write maildirsize in standart Maildir manner */
	sig_alarmcatch(sigalrm);

	for (i = 0; ; ++i) {
		tm = now();
		pid = getpid();
		buf = (char *)alloc(path.len + 17 + (2 * FMT_ULONG) + 2);
		if (buf == (char *)0)
			temp_nomem();
		s = buf;
		byte_copy(s, path.len, path.s); s += path.len;
		byte_copy(s, 17, "/tmp/maildirsize."); s += 17;
		s += fmt_ulong(s,maxtime); *s++ = '.';
		s += fmt_ulong(s,pid); *s++ = 0;
		if (stat(buf, &st) == -1) if (errno == error_noent) break;
		/* really should never get to this point */
		if (i == 2) _exit(1);
		sleep(2);
	}

	alarm(86400);

	if ((*fd = open(buf, O_RDWR|O_NDELAY|O_APPEND|O_CREAT, 0600)) == -1) {
		if (errno == error_noent) return 0;
		goto fail;
	}

	substdio_fdbuf(&ss,subwrite,*fd,writebuf,sizeof(writebuf));
	
	if (q->quota_size != 0) {
		if (substdio_bput(&ss, num, fmt_ulong(num, q->quota_size))
				== -1 )
			goto fail;
		if (substdio_bput(&ss,"S", 1) == -1)
			goto fail;
		if (q->quota_count != 0)
			if (substdio_bput(&ss,",", 1) == -1)
				goto fail;
	}
	if (q->quota_count != 0) {
		if (substdio_bput(&ss, num, fmt_ulong(num, q->quota_count))
				== -1)
			goto fail;
		if (substdio_bput(&ss,"C", 1) == -1 )
			goto fail;
	}
	if (substdio_bput(&ss,"\n", 1) == -1)
		goto fail;
	if (substdio_bput(&ss, num, fmt_ulong(num, q->size)) == -1)
		goto fail;
	if (substdio_bput(&ss, " ", 1) == -1)
		goto fail;
	if (substdio_bput(&ss, num, fmt_ulong(num, q->count)) == -1)
		goto fail;
	if (substdio_bput(&ss, "\n", 1) == -1)
		goto fail;
	if (substdio_flush(&ss) == -1)
		goto fail; 
	if (fsync(*fd) == -1)
		goto fail; 
	
	i = check_maxtime(maxtime);
	if (!stralloc_cats(&path, "maildirsize")) temp_nomem();
	if (!stralloc_0(&path)) temp_nomem();
	if (unlink(path.s) == -1 && errno != error_noent) goto fail;
	
	if (i) {
		/* race condition, don't write maildir size */
		unlink(buf);
		alloc_free(buf);
		*fd = -1;
		return -1;
	}
	if (link(buf,path.s) == -1) goto fail;
	unlink(buf);

	/* unset the alarm, else %*#! may happen */
	alarm(0);
	sig_alarmdefault();

	return 0;

fail: 
	strerr_warn3("Problems while trying to get maildirsize: ", 
			error_str(errno), ". (QUOTA #1.1.1)", 0);
	unlink(buf);
	*fd = -1;
	return -1;
}

static int
check_maxtime(time_t t)
/* check if a directory has changed, to avoid race conditions */
{
	direntry *dp;
	DIR *dirp;
	struct stat filest;
	unsigned int slen;
	int i;

	slen = path.len;
	if (!stralloc_0(&path)) temp_nomem();
	dirp = opendir(path.s);
	path.len = slen;
	
	i = 0;
	while (dirp && (dp = readdir(dirp)) != 0) {
		if (dp->d_name[0] == '.' &&
		    dp->d_name[1] != '\0' &&
		    dp->d_name[1] != '.'
#ifndef QUOTATRASH
		    && str_diff(".Trash", dp->d_name)
#endif
		   ) {

			path.len = slen;
			if (!stralloc_cats(&path, dp->d_name)) temp_nomem();
			if (!stralloc_cats(&path, "/cur")) temp_nomem();
			if (!stralloc_0(&path)) temp_nomem();
			if (stat(path.s, &filest) == 0
			    && filest.st_mtime > t) {
				i = 1;
				break;
			}
			path.len = slen;
			if (!stralloc_cats(&path, dp->d_name)) temp_nomem();
			if (!stralloc_cats(&path, "/new")) temp_nomem();
			if (!stralloc_0(&path)) temp_nomem();
			if (stat(path.s, &filest) == 0
			    && filest.st_mtime > t) {
				i = 1;
				break;
			}
		}
		if (!str_diff("new", dp->d_name)) {
			path.len = slen;
			if (!stralloc_cats(&path, "/new")) temp_nomem();
			if (stat(path.s, &filest) == 0
			    && filest.st_mtime > t) {
				i = 1;
				break;
			}
		}
		if (!str_diff("cur", dp->d_name)) {
			path.len = slen;
			if (!stralloc_cats(&path, "/cur")) temp_nomem();
			if (stat(path.s, &filest) == 0
			    && filest.st_mtime > t) {
				i = 1;
				break;
			}
		}
	}
	if (dirp) closedir(dirp);

	path.len = slen;
	return i;
}

static int
get_file_size(char *name, struct stat *st)
/* get the filesize of the file name in dir, via the name or a stat */
{
	char *s = name;
	unsigned int slen;

	while (*s) {
		if (*s != ',' || s[1] != 'S' || s[2] != '=') {
			s++;
		} else {
			s += 3;
			st->st_size = 0;
			while (*s >= '0' && *s <= '9')
				st->st_size = st->st_size*10 + (*s++ - '0');
			return 0;
		}
	}
	/* stat the file */
	slen = --path.len; /* path was zero terminated */
	if (!stralloc_cats(&path, name)) temp_nomem();
	if (!stralloc_0(&path)) temp_nomem();
	path.len = slen;

	if (stat(path.s, st) == 0) {
		if (!stralloc_0(&path)) temp_nomem();
		return 0;
	} else {
		if (!stralloc_0(&path)) temp_nomem();
		return -1;
	}
}

static void
calc_curnew(quota_t *q, time_t *maxtime)
/* calculate the size of the two dirs new and cur of a maildir 
 * (uses get_file_size) */
{
	struct stat		filest;
	direntry		*dp;
	DIR			*dirp;
	char			*f;
	int			i;

	if (!stralloc_cats(&path, "/new/")) temp_nomem();
	if (!stralloc_0(&path)) temp_nomem();
	
	for (i = 0; i < 2; i++) {
		/* update the latest modified time to avoid race conditions */
		if (stat(path.s, &filest) == 0 && filest.st_mtime > *maxtime)
			*maxtime = filest.st_mtime;

		dirp = opendir(path.s);
		/* start with new */
		while (dirp && (dp = readdir(dirp)) != 0) {
			f = dp->d_name;
			if ( *f == '.' ) continue; /* ignore all dot-files */
			while(*f) {
				if (*f != ':' || f[1] != '2' || f[2] != ',') {
					f++;
				} else {
					f += 3;
					while (	*f >= 'A'
						&& *f <= 'Z'
						&& *f != 'T') f++;
					break;
				}
			}
			if (*f == 'T') continue;
			/* get the file size */
			if(get_file_size(dp->d_name, &filest) == 0) {
				q->count++;
				q->size += (long)filest.st_size;
			} 
		}
		if (dirp) closedir(dirp);

		/* the same thing with cur */
		fmt_str(path.s + path.len - 5, "cur");
	}
}

static int
read5120(const char *fn, char* buf, int *len)
{
	int fd;
	int r;

	if ((fd = open(fn, O_RDWR|O_NDELAY|O_APPEND, 0600)) == -1) {
		if (errno == error_noent) return -1;
		strerr_die3x(111, "Unable to open maildirsize: ", 
				error_str(errno), " (QUOTA #1.5.1)");
	}
	
	*len = 0;
	for (;;) {
		r = read(fd, buf, 5120 - *len);
		if (r == -1) if (errno == error_intr) continue;
		if (*len >= 5120) { /* file to big */
			close(fd);
			unlink(path.s);
			return -1;
		}
		if (r == 0) return fd; /* no more data */
		*len += r;
		buf += r;
	}
}

