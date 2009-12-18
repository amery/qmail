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
#include "byte.h"
#include "case.h"
#include "error.h"
#include "getln.h"
#include "now.h"
#include "stralloc.h"
#include "substdio.h"

#include "qmail-ldap.h"
#include "mailmagic.h"

static unsigned int mypos;
static stralloc *mysa;

static void
sa_init(stralloc *header)
{
	mypos = 0;
	mysa = header;
}

static int
sa_read(int fd, void *buf, int len)
{
	int	t;

	t = mysa->len - mypos;
	if (t == 0) return 0;
	if (t < 0) {
		errno = error_io;
		return -1;
	}
	if (t > len) t = len;
	byte_copy(buf, t, mysa->s + mypos);
	mypos += t;
	return t;
}

static char buf[256];
static stralloc line = {0};

#ifndef REPLY_SUBJ
#define REPLY_SUBJ "Your Mail"
#endif

static int
magicsubject(stralloc *l, stralloc *h, stralloc *s)
{
	unsigned int i, j;
	
	j = l->len;
	for (i = 0; i < j; i++) {
		if (l->s[i] != '%') {
			if (!stralloc_append(h, &l->s[i])) return -1;
			continue;
		}
		if (case_startb(l->s + i, j - i, "%SUBJECT%") == 0) {
			if (!stralloc_append(h, &l->s[i])) return -1;
			continue;
		}
		i += 8; /* strlen("%SUBJECT%") - 1 */
		if (s == 0 || s->s == 0 || s->len == 0) {
			if (!stralloc_cats(h, REPLY_SUBJ)) return -1;
		} else {
			if (!stralloc_cat(h, s)) return -1;
		}
	}
	
	return 0;
}

int
headermagic(stralloc *mess, stralloc *header, stralloc *subj,
    struct mheader *h)
{
	substdio	ss;
	unsigned int	pos, i;
	int		match, w;
	
	if (!stralloc_copys(header, "")) return -1;
	for (i = 0; h[i].f != 0; i++) h[i].seen = 0;
	pos = 0; w = 0;

	sa_init(mess);
	substdio_fdbuf(&ss, sa_read, -1, buf, sizeof(buf));
	if (getln(&ss, &line, &match, '\n') != 0) return -1;
	if (match && case_diffb(line.s, line.len, "%HEADER%\n") == 0) {
		pos += line.len;
		for (;;) {
			if (getln(&ss, &line, &match, '\n') != 0) return -1;
			if (!match) break;
			pos += line.len;
			if (line.len <= 1) break;
			if (*line.s == '\t' || *line.s == ' ')
				if (w) {
					if (!stralloc_cat(header, &line))
						return -1;
					continue;
				}
			w = 0;
			for (i = 0; h[i].f != 0; i++) {
				if (case_startb(line.s, line.len, h[i].f) == 0)
					continue;
				if (h[i].type == DENY) break;
				if (h[i].type == FORCE) break;
				w = 1;
				h[i].seen = 1;
				if (h[i].type == SUBJECT) {
					if (magicsubject(&line,
						    header, subj) == -1)
						return -1;
					break;
				}
				if (!stralloc_cat(header, &line)) return -1;
			}
		}
	}

	for (i = 0; h[i].f != 0; i++)
		if (h[i].seen == 0 && h[i].v != 0)
			if (h[i].type != DENY ) {
				if (h[i].type == SUBJECT) {
					if (!stralloc_copys(&line, h[i].f))
						return -1;
					if (!stralloc_append(&line, " "))
						return -1;
					if (!stralloc_cats(&line, h[i].v))
						return -1;
					if (line.s[line.len-1] != '\n')
						if (!stralloc_append(&line,
							    "\n")) return -1;
					if (magicsubject(&line,
						    header, subj) == -1)
						return -1;
					continue;
				}
				if (!stralloc_cats(header, h[i].f)) return -1;
				if (!stralloc_append(header, " ")) return -1;
				if (!stralloc_cats(header, h[i].v)) return -1;
				if (header->s[header->len-1] != '\n')
					if (!stralloc_append(header, "\n"))
						return -1;
			}
	return pos;
}

static stralloc mimebound = {0};

int
mimemagichead(stralloc *h, stralloc *salt)
{
	if (!stralloc_copys(&mimebound, "--")) return -1;
	if (!stralloc_cat(&mimebound, salt)) return -1;

	if (!stralloc_cats(h, "Content-Type: multipart/mixed; boundary=\""))
		return -1;
	if (!stralloc_catb(h, mimebound.s + 2, mimebound.len - 2)) return -1;
	if (!stralloc_cats(h, "\"\n\n"
		    "This is a multi-part message in MIME format.\n"
		    "If you can read this your mail user agent does"
		    "not support MIME messages\n")) return -1;

	if (!stralloc_0(&mimebound)) return -1;
	return 0;
}

char *
mimemagic(void)
{
	return mimebound.s;
}

