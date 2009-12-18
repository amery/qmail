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
#include "env.h"
#include "open.h"
#include "qldap-debug.h"
#include "wait.h"

#include "pbsexec.h"

char *pbstool = 0;

void
pbsexec(void)
{
	char *(args[3]);
	int child, wstat;

	if (pbstool == 0 || *pbstool == 0) return;

	if (env_get("NOPBS")) return;

	switch (child = fork()) {
	case -1:
		return;
	case 0:
		/* the pbstool may not read or write to the connection */
		close(0); open_read("/dev/null");
		close(1); open_write("/dev/null");
		close(3);
		
		args[0] = pbstool;
		args[1] = 0;
		execvp(*args, args);
		_exit(111);
	}

	wait_pid(&wstat,child);
	if (wait_crashed(wstat))
		logit(2, "pbsexec: %s crashed\n", pbstool);
	else if (wait_exitcode(wstat))
		logit(2, "pbsexec: %s failed, exit code %d\n",
		    pbstool, wait_exitcode(wstat));
	else
		logit(64, "pbsexec: %s OK\n", pbstool);

	return;
}

