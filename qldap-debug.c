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
#include "output.h"
#include "qldap-debug.h"
#include "env.h"
#include "scan.h"
#include "readwrite.h"

#include <stdarg.h>

#ifdef ENABLE_PROFILE
#include <taia.h>
#endif

#ifdef DEBUG

/* 
 * Known LOGLEVELs: 
 *  1 = Error, only errors are reported (not verbose)
 *  2 = Warning, errors and warnings are reported (normaly not verbose)
 *  4 = Info, print some information (login name and success or fail)
 *  8 = Info^2 (more info), session forwarding and maildirmake ...
 * 16 = Debug, more information about authentication etc.
 * 32 = Debug^2 (more debug info), even more ...
 * 64 = LDAP-Debug, show everything in the ldap-module
 *128 = some more LDAP-Debug stuff (good for ldap test tool)
 *256 = PASSWD-Debug, this shows the encrypted and clear text passwords
 *      so use it with care 
 *1024= profiling output (if compiled with profile support)
 */

#define LOGLEN 256
static int addLOG;
static unsigned long loglevel;
substdio sslog;
char logbuffer[LOGLEN];

void
log_init(int fd, unsigned long mask, int via_spawn)
/* 
 * Known LOGLEVELs: 
 */
{
	char *a = env_get("LOGLEVEL");
	
	loglevel = 0;
	addLOG = via_spawn;
	if ( a && *a ) {
		scan_ulong(a, &loglevel);
	} else if ((a = env_get("DEBUGLEVEL")) && *a ) {
		scan_ulong(a, &loglevel);
	}
	loglevel &= mask;

	substdio_fdbuf(&sslog, subwrite, fd, logbuffer, sizeof(logbuffer) );
/*	logit(4, "LOGLEVEL set to %i\n", loglevel);
 */
}

void
logit(unsigned long level, const char *fmt, ...)
/* see va_output (output.c) */
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	ch = 15;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
	ch = 16;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	if ( substdio_flush(&sslog) == -1 ) return;
}

/* use logstart, logadd and logend with care, if there is no corresponding
   start or end starnge messages will be loged or some important messages 
   will be lost */
void
logstart(unsigned long level, const char *fmt, ...)
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	ch = 15;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
}

void
logadd(unsigned long level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
}

void
logend(unsigned long level, const char *fmt, ...)
{
	va_list ap;
	char ch;

	va_start(ap, fmt);
	if ( ! ( loglevel & level ) ) return;
	va_output(&sslog, fmt, ap);
	va_end(ap);
	ch = 16;
	if ( addLOG ) if ( substdio_put(&sslog, &ch, 1) ) return;
	if ( substdio_flush(&sslog) == -1 ) return;
}

void
profile(const char *s)
{
#ifdef ENABLE_PROFILE
	char buf[TAIA_PACK];
	struct taia t;

	taia_now(&t);
	taia_pack(buf,&t);
	logit(LOG_PROFILE, "PROFILE: %s @%s\n", s, buf); 
#endif
}
#else /* DEBUG */
void log_init(int fd, unsigned long mask, int via_spawn) {}
void logit(unsigned long level, const char *fmt, ...) {}
void logstart(unsigned long level, const char *fmt, ...) {}
void logadd(unsigned long level, const char *fmt, ...) {}
void logend(unsigned long level, const char *fmt, ...) {}
void profile(const char *s) {}
#endif
