/*
 * Copyright (c) 2005 Claudio Jeker,
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

#include "stralloc.h"
#include "xtext.h"

static int xtext_doit(stralloc *, stralloc *);
static const char ioHexArray[] = "0123456789abcdef";

static int
xtext_doit(stralloc *saout, stralloc *sain)
{
	unsigned int	n;
	char		x[3];
	unsigned char	c;

	if (!stralloc_ready(saout,sain->len))
		return (0);
	x[0] = '+';
	for (n = 0; n < sain->len; n++) {
		c = sain->s[n];
		if (c < 33 || c > 126 || c == '=' || c == '+') {
			x[1] = ioHexArray[(c >> 4) & 0x0f];
			x[2] = ioHexArray[c & 0x0f];
			if (!stralloc_catb(saout, x, sizeof(x)))
				return (0);
		} else
			if (!stralloc_append(saout, &c))
				return (0);
	}
	return (1);
}

int
xtext_needed(const char *s, unsigned int n)
{
	unsigned char	c;

	for (; n > 0; n--) {
		c = *s++;
		if (c < 33 || c > 126 || c == '=' || c == '+')
			return (1);
	}
	return (0);
}

int
xtext_quote(stralloc *saout, stralloc *sain)
{
	if (xtext_needed(sain->s, sain->len))
		return (xtext_doit(saout, sain));
	return (stralloc_copy(saout,sain));
}

