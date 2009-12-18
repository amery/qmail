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
#include "auto_qmail.h"
#include "control.h"
#include "error.h"
#include "fmt.h"
#include "getln.h"
#include "now.h"
#include "qmail.h"
#include "readwrite.h"
#include "seek.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"


#define FATAL "qmail-forward: fatal: "

void
usage(void)
{
	strerr_die1x(100,
	    "qmail-forward: usage: qmail-forward host sender recipient");
}

void
temp_nomem(void)
{
	strerr_die2x(111, FATAL, "Out of memory. (#4.3.0)");
}
void
temp_rewind(void)
{
	strerr_die2x(111, FATAL, "Unable to rewind message. (#4.3.0)");
}
void
temp_read(void)
{
	strerr_die3x(111, "Unable to read message: ",
	    error_str(errno), ". (#4.3.0)");
}
void
temp_fork(void)
{
	strerr_die3x(111, "Unable to fork: ", error_str(errno), ". (#4.3.0)");
}



char buf[4096];

stralloc me = {0};
stralloc dtline = {0};
stralloc messline = {0};

void bouncexf(void)
{
	substdio ss;
	int match;

	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));
	for (;;)
	{
		if (getln(&ss, &messline, &match, '\n') != 0) temp_read();
		if (!match) break;
		if (messline.len <= 1)
			break;
		if (messline.len == dtline.len)
			if (!str_diffn(messline.s, dtline.s, dtline.len))
				strerr_die2x(100, FATAL, 
				    "This message is looping: "
				    "it already has my Cluster-Delivered-To "
				    "line. (#5.4.6)\n");
	}
}

char strnum1[FMT_ULONG];
char strnum2[FMT_ULONG];

int
main (int argc, char **argv)
{
	struct qmail qqt;
	substdio ss;
	char *remote, *to, *from;
	const char *qqx;
	unsigned long qp;
	datetime_sec when;
	int match;
	unsigned int i;
	
	if (!(remote = argv[1])) usage();
	if (!(from = argv[2])) usage();
	if (!(to = argv[3])) usage();
	if (argv[4]) usage();
	
	if (chdir(auto_qmail) == -1)
		strerr_die4sys(111, FATAL, "Unable to switch to ",
		    auto_qmail, ": ");
	if (control_init() == -1)
		strerr_die2sys(111, FATAL, "Unable to read controls: ");
	if (control_readline(&me, "control/me") != 1)
		strerr_die2sys(111, FATAL, "Unable to read control/me: ");

	
	if (!stralloc_copys(&dtline, "Delivered-To: CLUSTERHOST "))
		temp_nomem();
	if (!stralloc_cat(&dtline, &me)) temp_nomem();
	if (!stralloc_cats(&dtline, " ")) temp_nomem();
	if (!stralloc_cats(&dtline, to)) temp_nomem();
	for (i = 0; i < dtline.len; ++i)
		if (dtline.s[i] == '\n')
			dtline.s[i] = '_';
	if (!stralloc_cats(&dtline, "\n")) temp_nomem();

	bouncexf();
	
	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, subread, 0, buf, sizeof(buf));

	if (qmail_remote(&qqt, remote) == -1) temp_fork();
	qp = qmail_qp(&qqt);

	qmail_put(&qqt, dtline.s, dtline.len);
	do {
		if (getln(&ss, &messline, &match, '\n') != 0) {
			qmail_fail(&qqt);
			break;
		}
		qmail_put(&qqt, messline.s, messline.len);
	} while (match);
	qmail_from(&qqt, from);
	qmail_to(&qqt, to);
	qqx = qmail_close(&qqt);
	if (*qqx) 
		strerr_die3x(*qqx == 'D' ? 100 : 111,
		    "Unable to cluster-forward message: ", qqx + 1, ".");
	when = now();
	strnum1[fmt_ulong(strnum1, (unsigned long) when)] = 0;
	strnum2[fmt_ulong(strnum2, qp)] = 0;
	strerr_die5x(0, "qmail-forward: ok ", strnum1, " qp ", strnum2, ".");
	/* NOTREACHED */
	return 0;
}

