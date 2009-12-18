#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "substdio.h"
#include "strerr.h"
#include "error.h"
#include "open.h"
#include "readwrite.h"
#include "exit.h"
#include "fifo.h"

extern void hier();

#define FATAL "install: fatal: "

int fdsourcedir = -1;

void h(home,uid,gid,mode)
const char *home;
int uid;
int gid;
int mode;
{
  if (mkdir(home,0700) == -1)
    if (errno != error_exist)
      strerr_die4sys(111,FATAL,"unable to mkdir ",home,": ");
  if (chown(home,uid,gid) == -1)
    strerr_die4sys(111,FATAL,"unable to chown ",home,": ");
  if (chmod(home,mode) == -1)
    strerr_die4sys(111,FATAL,"unable to chmod ",home,": ");
}

void d(home,subdir,uid,gid,mode)
const char *home;
const char *subdir;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
  if (mkdir(subdir,0700) == -1)
    if (errno != error_exist)
      strerr_die6sys(111,FATAL,"unable to mkdir ",home,"/",subdir,": ");
  if (chown(subdir,uid,gid) == -1)
    strerr_die6sys(111,FATAL,"unable to chown ",home,"/",subdir,": ");
  if (chmod(subdir,mode) == -1)
    strerr_die6sys(111,FATAL,"unable to chmod ",home,"/",subdir,": ");
}

void p(home,fifo,uid,gid,mode)
const char *home;
const char *fifo;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
  if (fifo_make(fifo,0700) == -1)
    if (errno != error_exist)
      strerr_die6sys(111,FATAL,"unable to mkfifo ",home,"/",fifo,": ");
  if (chown(fifo,uid,gid) == -1)
    strerr_die6sys(111,FATAL,"unable to chown ",home,"/",fifo,": ");
  if (chmod(fifo,mode) == -1)
    strerr_die6sys(111,FATAL,"unable to chmod ",home,"/",fifo,": ");
}

char inbuf[SUBSTDIO_INSIZE];
char outbuf[SUBSTDIO_OUTSIZE];
substdio ssin;
substdio ssout;

void c(home,subdir,file,uid,gid,mode)
const char *home;
const char *subdir;
const char *file;
int uid;
int gid;
int mode;
{
  int fdin;
  int fdout;

  if (fchdir(fdsourcedir) == -1)
    strerr_die2sys(111,FATAL,"unable to switch back to source directory: ");

  fdin = open_read(file);
  if (fdin == -1)
    strerr_die4sys(111,FATAL,"unable to read ",file,": ");
  substdio_fdbuf(&ssin,subread,fdin,inbuf,sizeof inbuf);

  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
  if (chdir(subdir) == -1)
    strerr_die6sys(111,FATAL,"unable to switch to ",home,"/",subdir,": ");

  fdout = open_trunc(file);
  if (fdout == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  substdio_fdbuf(&ssout,subwrite,fdout,outbuf,sizeof outbuf);

  switch(substdio_copy(&ssout,&ssin)) {
    case -2:
      strerr_die4sys(111,FATAL,"unable to read ",file,": ");
    case -3:
      strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  }

  close(fdin);
  if (substdio_flush(&ssout) == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  if (fsync(fdout) == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  if (close(fdout) == -1) /* NFS silliness */
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");

  if (chown(file,uid,gid) == -1)
    strerr_die6sys(111,FATAL,"unable to chown .../",subdir,"/",file,": ");
  if (chmod(file,mode) == -1)
    strerr_die6sys(111,FATAL,"unable to chmod .../",subdir,"/",file,": ");
}

void C(home,subdir,file,source,uid,gid,mode)
const char *home;
const char *subdir;
const char *file;
const char *source;
int uid;
int gid;
int mode;
{
  struct stat st;
  int fdin;
  int fdout;

  if (fchdir(fdsourcedir) == -1)
    strerr_die2sys(111,FATAL,"unable to switch back to source directory: ");

  fdin = open_read(source);
  if (fdin == -1)
    strerr_die4sys(111,FATAL,"unable to read ",source,": ");
  substdio_fdbuf(&ssin,subread,fdin,inbuf,sizeof inbuf);

  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
  if (chdir(subdir) == -1)
    strerr_die6sys(111,FATAL,"unable to switch to ",home,"/",subdir,": ");

  /* if file seems to exist don't overwrite */
  if (stat(file, &st) == 0) {
    close(fdin);
    return;
  }
  
  fdout = open_trunc(file);
  if (fdout == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  substdio_fdbuf(&ssout,subwrite,fdout,outbuf,sizeof outbuf);

  switch(substdio_copy(&ssout,&ssin)) {
    case -2:
      strerr_die4sys(111,FATAL,"unable to read ",source,": ");
    case -3:
      strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  }

  close(fdin);
  if (substdio_flush(&ssout) == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  if (fsync(fdout) == -1)
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");
  if (close(fdout) == -1) /* NFS silliness */
    strerr_die6sys(111,FATAL,"unable to write .../",subdir,"/",file,": ");

  if (chown(file,uid,gid) == -1)
    strerr_die6sys(111,FATAL,"unable to chown .../",subdir,"/",file,": ");
  if (chmod(file,mode) == -1)
    strerr_die6sys(111,FATAL,"unable to chmod .../",subdir,"/",file,": ");
}

void l(home,subdir,logdir,loguser,uid,gid,mode)
const char *home;
const char *subdir;
const char *logdir;
const char *loguser;
int uid;
int gid;
int mode;
{
  int fdout;
  struct stat st;

  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");
  if (chdir(subdir) == -1)
    strerr_die6sys(111,FATAL,"unable to switch to ",home,"/",subdir,": ");

  /* if file seems to exist don't overwrite */
  if (stat("run", &st) == 0) return;
  
  fdout = open_trunc("run");
  if (fdout == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  substdio_fdbuf(&ssout,subwrite,fdout,outbuf,sizeof outbuf);

  /* write log script */
  if (substdio_puts(&ssout,
        "#!/bin/sh\n\nexec setuidgid ") == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, loguser) == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, " multilog t ") == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, home) == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, "/") == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, logdir) == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (substdio_puts(&ssout, "\n\n") == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");

  if (substdio_flush(&ssout) == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (fsync(fdout) == -1)
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");
  if (close(fdout) == -1) /* NFS silliness */
    strerr_die4sys(111,FATAL,"unable to write .../",subdir,"/run: ");

  if (chown("run",uid,gid) == -1)
    strerr_die4sys(111,FATAL,"unable to chown .../",subdir,"/run: ");
  if (chmod("run",mode) == -1)
    strerr_die4sys(111,FATAL,"unable to chmod .../",subdir,"/run: ");
}


void z(home,file,len,uid,gid,mode)
const char *home;
const char *file;
int len;
int uid;
int gid;
int mode;
{
  int fdout;

  if (chdir(home) == -1)
    strerr_die4sys(111,FATAL,"unable to switch to ",home,": ");

  fdout = open_trunc(file);
  if (fdout == -1)
    strerr_die6sys(111,FATAL,"unable to write ",home,"/",file,": ");
  substdio_fdbuf(&ssout,subwrite,fdout,outbuf,sizeof outbuf);

  while (len-- > 0)
    if (substdio_put(&ssout,"",1) == -1)
      strerr_die6sys(111,FATAL,"unable to write ",home,"/",file,": ");

  if (substdio_flush(&ssout) == -1)
    strerr_die6sys(111,FATAL,"unable to write ",home,"/",file,": ");
  if (fsync(fdout) == -1)
    strerr_die6sys(111,FATAL,"unable to write ",home,"/",file,": ");
  if (close(fdout) == -1) /* NFS silliness */
    strerr_die6sys(111,FATAL,"unable to write ",home,"/",file,": ");

  if (chown(file,uid,gid) == -1)
    strerr_die6sys(111,FATAL,"unable to chown ",home,"/",file,": ");
  if (chmod(file,mode) == -1)
    strerr_die6sys(111,FATAL,"unable to chmod ",home,"/",file,": ");
}

int main()
{
  fdsourcedir = open_read(".");
  if (fdsourcedir == -1)
    strerr_die2sys(111,FATAL,"unable to open current directory: ");

  umask(077);
  hier();
  return 0;
}
