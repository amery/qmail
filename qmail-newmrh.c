#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "getln.h"
#include "exit.h"
#include "readwrite.h"
#include "open.h"
#include "auto_qmail.h"
#include "cdb_make.h"
#include "case.h"

#define FATAL "qmail-newmrh: fatal: "

void die_read()
{
  strerr_die2sys(111,FATAL,"unable to read control/morercpthosts: ");
}
void die_write()
{
  strerr_die2sys(111,FATAL,"unable to write to control/morercpthosts.tmp: ");
}

char inbuf[1024];
substdio ssin;

int fd;
int fdtemp;

struct cdb_make cdbm;
stralloc line = {0};
int match;

int main()
{
  umask(033);
  if (chdir(auto_qmail) == -1)
    strerr_die4sys(111,FATAL,"unable to chdir to ",auto_qmail,": ");

  fd = open_read("control/morercpthosts");
  if (fd == -1) die_read();

  substdio_fdbuf(&ssin,subread,fd,inbuf,sizeof inbuf);

  fdtemp = open_trunc("control/morercpthosts.tmp");
  if (fdtemp == -1) die_write();

  if (cdb_make_start(&cdbm,fdtemp) == -1) die_write();

  for (;;) {
    if (getln(&ssin,&line,&match,'\n') != 0) die_read();
    case_lowerb(line.s,line.len);
    while (line.len) {
      if (line.s[line.len - 1] == ' ') { --line.len; continue; }
      if (line.s[line.len - 1] == '\n') { --line.len; continue; }
      if (line.s[line.len - 1] == '\t') { --line.len; continue; }
      if (line.s[0] != '#')
	if (cdb_make_add(&cdbm,line.s,line.len,"",0) == -1)
	  die_write();
      break;
    }
    if (!match) break;
  }

  if (cdb_make_finish(&cdbm) == -1) die_write();
  if (fsync(fdtemp) == -1) die_write();
  if (close(fdtemp) == -1) die_write(); /* NFS stupidity */
  if (rename("control/morercpthosts.tmp","control/morercpthosts.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move control/morercpthosts.tmp to control/morercpthosts.cdb");

  return 0;
}
