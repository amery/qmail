/*
 * Copyright (c) 2001-2004 Claudio Jeker,
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
#include "substdio.h"
#include "fmt.h"
#include "str.h"
#include "scan.h"
#include "output.h"

#include <stdarg.h>

char num[FMT_ULONG];

static const char nullString[] = "(null pointer)";
static const char ioHexArray[] = "0123456789abcdef";

static int fmt_hexulong(char *s, unsigned long x) 
	/* s has to be allready allocated, use at least FMT_ULONG chars 
	 * 40 chars should be enough for a 20 byte unsigned long (2^160) 
	 * so djb's fmt_ulong would first fail ;-) */
{
	unsigned int i;

	for (i = 0; i < sizeof(unsigned long) * 2; i++) {
		*s++ = (ioHexArray[(x >> (sizeof(unsigned long)*8 - 4)) & 0xf]);
		x = x << 4;
	}
	return sizeof(unsigned long) * 2;
}

void va_output(substdio *ss, char const *fmt, va_list args)
/*
 * works like vprintf has the format options %i, ...
 * all flags (#, 0, -, ' ', +, ' ... ) are not supported if not special noted
 * Also not supported are all options for foating-point numbers 
 * (not needed in qmail)
 * Supported conversion specifiers: diouxcsSp%
 * diux are for integer (long) conversions
 * c is a single unsigned char
 * s is a zero terminated string
 * S is a stralloc object (should not be zero terminated (else the zero 
 *   will be printed))
 * p is the hex address of a generic pointer (void *)
 * % is the % sign
 */
{
	unsigned long ul;
	long l;
	char *s;
	char const *start;
	char const *cur;
	void *p;
	unsigned char c;
	stralloc *sa;

	start = fmt;
	cur = fmt;
	if (!cur) return;
	while (*cur) {
		if (*cur == '%') {
			if ( substdio_put(ss, start, cur-start) == -1 ) return;
			/*
			 * no need to care if the output is save qmail-send
			 * looks if the output is save
			 */
			cur++;
			switch (*cur) {
			case 'd':
			case 'i':
				l = va_arg(args, long);
				if (l < 0) {
					/* negativ number, d and i are signed */
					l *= -1;
					if (substdio_put(ss, "-", 1) == -1)
						return;
				}
				ul = (unsigned long)l;
				if (substdio_put(ss, num, fmt_ulong(num, ul))) 
					return;
				break;
			case 'u':
				ul = va_arg(args, unsigned long);
				if (substdio_put(ss, num, fmt_ulong(num, ul))) 
					return;
				break;
			case 's':
				s = va_arg(args, char *);
				if (!s) {
					if (substdio_put(ss, nullString, 
						    str_len(nullString))) 
						return;
					break;
				}
				if (substdio_put(ss, s, str_len(s))) return;
				break;
			case 'S':
				sa = va_arg(args, stralloc *);
				if (!sa) {
					if (substdio_put(ss, nullString, 
						    str_len(nullString)))
						return;
					break;
				}
				if (substdio_put(ss, sa->s, sa->len))
					return;
				break;
			case '%':
				if (substdio_put(ss, "%", 1) == -1)
					return;
				break;
			case 'p':
				p = va_arg(args, void *);
				ul = (unsigned long)p;
				if (substdio_put(ss, "0x", 2)) return;
				if (substdio_put(ss, num,
					    fmt_hexulong(num, ul))) 
					return;
				break;
			case 'x':
				ul = va_arg(args, unsigned long);
				if (substdio_put(ss, "0x", 2)) return;
				if (substdio_put(ss, num,
					    fmt_hexulong(num, ul))) 
					return;
				break;
			case 'c':
				c = (unsigned char)
				    va_arg(args, unsigned int);
				substdio_BPUTC(ss, c);
				break;
			}
			start = ++cur; 
		} else {
			++cur;
		}
	}
	if (substdio_put(ss, start, cur-start) == -1) return;
}

void output(substdio *ss, char const *fmt, ...)
	/* see va_output */
{
	va_list args;

	va_start(args,fmt);
	va_output(ss, fmt, args);
	va_end(args);
	if (substdio_flush(ss) == -1) return; 
}

