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
#include "coe.h"
#include "fd.h"
#include "substdio.h"
#include "str.h"
#include "stralloc.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "wait.h"

#include "smtpcall.h"

int call_getln(substdio *ss, stralloc *l)
{
  int i;
  if (!stralloc_copys(l, "")) return -1;
  for (;;) {
    if (!stralloc_readyplus(l,1)) return -1;
    i = substdio_get(ss, l->s + l->len, 1);
    if (i != 1) return i;
    if (l->s[l->len] == '\n') break;
    ++l->len;
  }
  if (l->len > 0) if (l->s[l->len-1] == '\r') --l->len;
  l->s[l->len] = 0;
  return l->len;
}

int
call_getc(struct call *cc, char *c)
{
	int r;
	if (cc->flagerr || cc->flagabort) return -1;
	r = substdio_get(&cc->ssfrom, c, 1);
	if (r == -1) {
		cc->flagerr = 1;
		return -1;
	}
	return r;
}

int
call_put(struct call *cc, const char *s, unsigned int len)
{
	if (cc->flagerr || cc->flagabort) return -1;
	if (cc->flagstar && str_diffn(s, "*", len) == 0) {
		cc->flagabort = 1;
		return -1;
	}
	if (substdio_put(&cc->ssto, s, len) == -1) {
		cc->flagerr = 1;
		return -1;
	}
	return 0;
}

int
call_puts(struct call *cc, const char *s)
{
	if (cc->flagerr || cc->flagabort) return -1;
	if (cc->flagstar && str_diff(s, "*") == 0) {
		cc->flagabort = 1;
		return -1;
	}
	if (substdio_puts(&cc->ssto, s) == -1) {
		cc->flagerr = 1;
		return -1;
	}
	return 0;
}

int
call_flush(struct call *cc)
{
	if (cc->flagerr || cc->flagabort) return -1;
	if (substdio_flush(&cc->ssto) == -1) {
		cc->flagerr = 1;
		return -1;
	}
	return 0;

}

int
call_putflush(struct call *cc, const char *s, unsigned int len)
{
	if (call_put(cc, s, len) == -1) return -1;
        if (call_flush(cc) == -1) return -1;
	return 0;
}

int
call_putsflush(struct call *cc, const char *s)
{
	if (call_puts(cc, s) == -1) return -1;
        if (call_flush(cc) == -1) return -1;
	return 0;
}

static int mytimeout = 10;

static int
mywrite(int fd, void *buf, int len)
{
	return timeoutwrite(mytimeout,fd,buf,len);
}

static int
myread(int fd, void *buf, int len)
{
	return timeoutread(mytimeout,fd,buf,len);
}

int
call_open(struct call *cc, const char *prog, int timeout, int flagstar)
{
  int pit[2];
  int pif[2];
  const char *(args[2]);

  args[0] = prog;
  args[1] = 0;

  if (pipe(pit) == -1) return -1;
  if (pipe(pif) == -1) { close(pit[0]); close(pit[1]); return -1; }
 
  switch(cc->pid = vfork()) {
    case -1:
      close(pit[0]); close(pit[1]);
      close(pif[0]); close(pif[1]);
      return -1;
    case 0:
      close(pit[1]);
      close(pif[0]);
      if (fd_move(0,pit[0]) == -1) _exit(120);
      if (fd_move(1,pif[1]) == -1) _exit(120);
      if (chdir(auto_qmail) == -1) _exit(61);
      execv(*args,(char **)args);
      _exit(120);
  }

  if (timeout != 0) mytimeout = timeout;
  cc->flagerr = 0;
  cc->flagabort = 0;
  cc->flagstar = flagstar;
  cc->tofd = pit[1]; close(pit[0]);
  cc->fromfd = pif[0]; close(pif[1]);
  coe(cc->tofd); coe(cc->fromfd);
  substdio_fdbuf(&cc->ssto, mywrite, cc->tofd,
      cc->tobuf, sizeof(cc->tobuf));
  substdio_fdbuf(&cc->ssfrom, myread, cc->fromfd,
      cc->frombuf, sizeof(cc->frombuf));
  return 0;
}

void
call_close(struct call *cc)
{
	int wstat;
	int r;
	char ch;
	
	if ((long)cc->pid == -1) return; /* nothing running */
	call_flush(cc);
	close(cc->tofd);
	while ((r = call_getc(cc, &ch)) == 1) ;
	if (r == -1) ; /* bad thing happend but who cares */
	close(cc->fromfd);
      
	wait_pid(&wstat,cc->pid); /* just kill the zombie */
}

const char *
auth_close(struct call *cc, stralloc *user, const char *pre)
{
	const char *s;
	int wstat;
	int exitcode;
	char c;

	s = 0; c = 0;
	if ((long)cc->pid == -1)
		return "454 unable to start authentication process. "
		    "(#4.3.0)\r\n";
	
	if (cc->flagabort)
		s = "501 authentication exchange aborted. (#4.3.0)\r\n";
	if (cc->flagerr)
		s = "454 authentication process write failure. (#4.3.0)\r\n";
	
	if (!cc->flagerr && !cc->flagabort) {
		if (call_getc(cc, &c) == -1) {
			s = "454 authentication process read failure. "
			    "(#4.3.0)\r\n";
		} else
		switch (c) {
		case 'K':
			if (!stralloc_copys(user, pre!=0?pre:"")) {
				s = "421 out of memory (#4.3.0)\r\n"; 
				break;
			}
			while (call_getc(cc, &c) == 1) {
				if (!stralloc_append(user, &c)) {
					s = "421 out of memory (#4.3.0)\r\n"; 
					break;
				}
			}
			if (cc->flagerr)
				s = "454 authentication process read "
				    "failure. (#4.3.0)\r\n";
			else
				s = "235 nice to meet you\r\n";
			break;
		case 'D':
			s = "535 authentication failure\r\n";
			break;
		case 'Z':
			s = "501 authentication exchange failed\r\n";
			break;
		default:
			s = "454 authentication process failure. (#4.3.0)\r\n";
			break;
		}
	}
	close(cc->tofd);
	close(cc->fromfd);
      
	if ((unsigned long)wait_pid(&wstat,cc->pid) != cc->pid)
		return "454 authentication waitpid surprise (#4.3.0)\r\n";
	if (wait_crashed(wstat))
		return "454 authentication process crashed (#4.3.0)\r\n";
	exitcode = wait_exitcode(wstat);
	switch (exitcode) {
	case 0:
		return s;
	default:
		return "454 temporary authentication failure (#4.3.0)\r\n";
	}
}

