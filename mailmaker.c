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
#ifdef AUTOMAILDIRMAKE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include "error.h"
#include "open.h"
#include "qldap-errno.h"

#include "mailmaker.h"

/*
 * XXX the maildirmake stuff is directly in qmail-local.c and qmail-pop3d.c
 * XXX this is simpler and better (Perhaps I'll find a better way sometimes) ;-)
 * XXX BULLSHIT! Simpler and better, was I on drugs? This needs definitifly a 
 * XXX rewrite and while doing that I can also fix the problem with courier.
 */
static int makedir(const char *);

static int
makedir(const char *dir)
{
	struct	stat st;
	
	if (stat(dir, &st) == -1) {
		if (errno == error_noent) {
			if (mkdir(dir,0700) == -1) return ERRNO;
		} else 
			return ERRNO;
	} else if (!S_ISDIR(st.st_mode))
		return MAILDIR_CORRUPT;

	return OK;
}

int
maildir_make(char *maildir)
{
	int	dirfd, oldmask, r, se;

	oldmask = umask(077);
	dirfd = open_read(".");
	if (dirfd == -1)
		return ERRNO;
	if (chdir(maildir) == -1) {
		if ((r = makedir(maildir)) != OK) goto fail;
		if (chdir(maildir) == -1) {
			if (errno == ENOTDIR) {
				r = MAILDIR_CORRUPT;
				goto fail;
			} else {
				r = ERRNO;
				goto fail;
			}
		}
	}
	if ((r = makedir("tmp")) != OK) goto fail;
	if ((r = makedir("cur")) != OK) goto fail;
	if ((r = makedir("new")) != OK) goto fail;

	umask(oldmask);
	if (fchdir(dirfd) == -1) {
		r = ERRNO;
		goto fail;
	}
	close(dirfd);
	return OK;

fail:
	se = errno;
	umask(oldmask);
	fchdir(dirfd);
	close(dirfd);
	errno = se;
	return r;
}
#endif

