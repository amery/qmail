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
 * Based on similar code by D. J. Bernstein
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include "auto_qmail.h"
#include "case.h"
#include "cdb_make.h"
#include "exit.h"
#include "getln.h"
#include "open.h"
#include "readwrite.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"

#define FATAL "qmail-cdb: fatal: "

void die_read(void)
{
  strerr_die2sys(111,FATAL,"unable to read from stdin: ");
}
void die_write(const char *f)
{
  strerr_die4sys(111,FATAL,"unable to write to ", f, ": ");
}

char inbuf[1024];
substdio ssin;

int fd;
int fdtemp;

struct cdb_make cdbm;
stralloc line = {0};
int match;

int main(int argc, char **argv)
{
  umask(033);

  if (argc != 3)
    strerr_die1sys(111,"qmail-cdb: usage: qmail-cdb rules.cdb rules.tmp");

  substdio_fdbuf(&ssin,subread,0,inbuf,sizeof inbuf);

  fdtemp = open_trunc(argv[2]);
  if (fdtemp == -1) die_write(argv[2]);

  if (cdb_make_start(&cdbm,fdtemp) == -1) die_write(argv[2]);

  for (;;) {
    if (getln(&ssin,&line,&match,'\n') != 0) die_read();
    case_lowerb(line.s,line.len);
    while (line.len) {
      if (line.s[line.len - 1] == ' ') { --line.len; continue; }
      if (line.s[line.len - 1] == '\n') { --line.len; continue; }
      if (line.s[line.len - 1] == '\t') { --line.len; continue; }
      if (line.s[0] != '#')
	if (cdb_make_add(&cdbm,line.s,line.len,"",0) == -1)
	  die_write(argv[2]);
      break;
    }
    if (!match) break;
  }

  if (cdb_make_finish(&cdbm) == -1) die_write(argv[2]);
  if (fsync(fdtemp) == -1) die_write(argv[2]);
  if (close(fdtemp) == -1) die_write(argv[2]); /* NFS stupidity */
  if (rename(argv[2],argv[1]) == -1)
    strerr_die5sys(111, FATAL, "unable to move ", argv[2], " to ", argv[1]);

  return 0;
}
