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

/*
 * Code and idea is based on a patch by Russel Nelson.
 */

#ifdef SMTPEXECCHECK
#include "byte.h"
#include "case.h"
#include "control.h"
#include "env.h"
#include "qmail.h"
#include "str.h"
#include "stralloc.h"

#include "execcheck.h"

extern void die_nomem(); /* needed error function from qmail-smtpd,c */
extern void die_control();

static int checkexecutable = 0;
static int flagexecutable;
static stralloc signatures = {0};

void
execcheck_setup(void)
{
	if (env_get("REJECTEXEC")) checkexecutable = 1;
	switch (control_readfile(&signatures,"control/signatures",0)) {
	case 0:
		checkexecutable = 0;
		break;
	case 1:
		break;
	default:
		die_control();
	}
}

int
execcheck_on(void)
{
	return checkexecutable;
}

int
execcheck_flag(void)
{
	return flagexecutable;
}

static int
signatures_match(stralloc *line, char *sig)
{
	unsigned int	k;

	for (k = 0; k < line->len && *sig; k++, sig++)
		if (*sig != '*')
			if (*sig != line->s[k]) return 0;
	if (*sig) return 0;
	return 1;
}

static int
signatures_check(stralloc *line)
{
	unsigned int	i, j;

	for (i = j = 0; i < signatures.len; i++)
		if (!signatures.s[i]) {
			if (signatures_match(line, signatures.s + j))
				return 1;
			j = i+1;
		}
	return 0;
}

static int linespastheader;	/* = 0 if in header (mime or mail)
			 	 * = 1 line after blank line
				 * = 2 somewhere in body
				 */
static unsigned int boundary_start;
static unsigned int boundary_len;
static int flagrfc822;
static char linetype;

static stralloc line = {0};
static stralloc content = {0};
static stralloc boundary = {0};
static stralloc token = {0};

static void
parse_token(void)
{
	if (token.len == 0 || *token.s == '\0')
		return;

	if (case_startb(token.s, token.len, "boundary=")) {
		/*
		 * push the current boundary.
		 * Append a null and remember start.
		 */
		boundary_start = boundary.len;
		if (!stralloc_cats(&boundary, "--"))
			die_nomem();
		if (!stralloc_cats(&boundary, token.s + 9))
			die_nomem();
		boundary_len = boundary.len - boundary_start;
		if (!stralloc_0(&boundary))
			die_nomem();
		return;
	}
	if (!case_diffb(token.s, token.len, "message/rfc822")) {
		flagrfc822 = 1;
		return;
	}
}

static void
parse_contenttype(void)
{
	char	*c;
	int	flagquoted = 0;
	int	flagcomment = 0;

	if (content.len == 0) /* NO MIME header */
		return;

	if (!stralloc_0(&content)) die_nomem();

	for (c = content.s; *c != '\0'; ) {
		for (; *c != '\0'; c++)
			if (*c != ' ' && *c != '\t' && *c != ';')
				break;

		if (!stralloc_copys(&token, "")) die_nomem();
		for (; *c != '\0'; c++)
			switch (*c) {
			case ' ':
			case '\t':
			case ';':
				if (flagquoted)
					break;
				goto token_done;
			case '"':
				if (flagquoted)
					flagquoted = 0;
				else
					flagquoted = 1;
				break;
			case '(':
				if (flagquoted) {
					if (!stralloc_append(&token, c))
					       	die_nomem();
					break;
				}
				flagcomment = 1;
				break;
			case ')':
				if (flagquoted) {
					if (!stralloc_append(&token, c))
						die_nomem();
					break;
				}
				flagcomment = 0;
				break;
			default:
				if (flagcomment)
					break;
				if (!stralloc_append(&token, c)) die_nomem();
				break;
			}
token_done:
		if (!stralloc_0(&token)) die_nomem();
		parse_token();
	}
}

void
execcheck_start(void)
{
	boundary.len = 0;
	content.len = 0;
	linespastheader = 0;
	boundary_start = 0;
	boundary_len = 0;
	flagexecutable = 0;
	flagrfc822 = 0;
	linetype = ' ';
}

void
execcheck_put(struct qmail *qq, const char *ch)
{
	if (!checkexecutable)
		return;

	/* already bad so leave it */
	if (flagexecutable)
		return;

	if (line.len < 1024)
		if (!stralloc_catb(&line,ch,1)) die_nomem();

	if (*ch != '\n')
		/* wait until we have a entire line together */
		return;

	if (linespastheader == 0) {
		/*
		 * in mail or mime header, search for content-type
		 * and possible boundary
		 */
		if (line.len == 1) {	/* end of header */
			linespastheader = 1;
			if (content.len) /* MIME header */
				parse_contenttype();
			if (flagrfc822) {
				/* now the forwarded rfc822 header is comming */
				linespastheader = 0;
				flagrfc822 = 0;
			}
		} else {	/* header lines */
			if (*line.s == ' ' || *line.s == '\t') {
				switch(linetype) {
				case 'C':
					if (!stralloc_catb(&content,
						    line.s, line.len-1))
						die_nomem();
					break;
				default:
					break;
				}
			} else {
				if (case_startb(line.s, line.len,
					    "content-type:")) {
					if (!stralloc_copyb(&content,
						    line.s+13, line.len-14))
						die_nomem();
					linetype = 'C';
				} else {
					linetype = ' ';
				}
			}
		}
	} else {	/* non-header lines */
		if (boundary_len && *line.s == '-' &&
		    stralloc_starts(&line,boundary.s + boundary_start)) {
			/* mime boundary matched */
			if (line.len > boundary_len + 2 &&
			    !str_diffn(line.s + boundary_len, "--", 2)) {
				/* end marker - pop last boundary */
				linespastheader = 2;
				if (boundary_start) {
					boundary.len = boundary_start;
					boundary_start = byte_rchr(boundary.s,
					    boundary.len - 1, '\0');
					if (boundary_start + 1 >= boundary.len)
						boundary_start = 0;
					boundary_len = boundary.len - 1 -
					    boundary_start;
				} else
					boundary_len = 0;
			} else
				linespastheader = 0;
		} else if (linespastheader == 1) {
			if (signatures_check(&line)) {
				flagexecutable = 1;
				qmail_fail(qq);
			}
			linespastheader = 2;
		}
	}
	line.len = 0;
}

#endif

