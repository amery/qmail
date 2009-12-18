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
#ifdef AUTOHOMEDIRMAKE
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "control.h"
#include "open.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qlx.h"
#include "stralloc.h"
#include "wait.h"

#include "dirmaker.h"


static stralloc	dirmaker = {0};

int
dirmaker_init(void)
/* ~control/dirmaker SHOULD to be only writeable for root */
{
	if (control_rldef(&dirmaker, "control/dirmaker", 0, "") == -1)
		return -1;
	if (!stralloc_0(&dirmaker))
		return -1;
	logit(64, "init: control/dirmaker: %s\n", dirmaker.s);
	return 0;
}

int
dirmaker_make(const char *home, const char *maildir)
{
	char *(dirargs[3]);
	int child, wstat;

	if (dirmaker.s == 0 || dirmaker.len < 2)
		return MAILDIR_UNCONF;
	
	switch(child = fork()) {
		case -1:
			if (error_temp(errno)) return MAILDIR_FAILED;
			return MAILDIR_HARD;
		case 0:
			dirargs[0] = dirmaker.s; dirargs[1] = (char *)home;
			dirargs[2] = (char *)maildir; dirargs[3] = 0;
			execvp(*dirargs,dirargs);
			if (error_temp(errno)) _exit(QLX_EXECSOFT);
			_exit(QLX_EXECHARD);
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat)) {
		return MAILDIR_CRASHED;
	}
	switch(wait_exitcode(wstat)) {
		case 0:
			return OK;
		case 100: case QLX_EXECHARD:
			return MAILDIR_HARD;
		default:
			return MAILDIR_FAILED;
	}
}
#endif

