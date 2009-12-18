#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "readwrite.h"
#include "sig.h"
#include "env.h"
#include "byte.h"
#include "exit.h"
#include "fork.h"
#include "open.h"
#include "wait.h"
#include "lock.h"
#include "seek.h"
#include "substdio.h"
#include "getln.h"
#include "strerr.h"
#include "subfd.h"
#include "sgetopt.h"
#include "alloc.h"
#include "error.h"
#include "stralloc.h"
#include "fmt.h"
#include "str.h"
#include "now.h"
#include "case.h"
#include "quote.h"
#include "qmail.h"
#include "slurpclose.h"
#include "myctime.h"
#include "gfrom.h"
#include "auto_patrn.h"

#include "qmail-ldap.h"
#include "qldap-errno.h"
#include "auto_qmail.h"
#include "scan.h"
#include "maildir++.h"
#ifdef AUTOMAILDIRMAKE
#include "mailmaker.h"
#endif

void usage() { strerr_die1x(100,"qmail-local: usage: qmail-local [ -nN ] user homedir local dash ext domain sender aliasempty"); }

void temp_nomem() { strerr_die1x(111,"Out of memory. (#4.3.0)"); }
void temp_rewind() { strerr_die1x(111,"Unable to rewind message. (#4.3.0)"); }
void temp_childcrashed() { strerr_die1x(111,"Aack, child crashed. (#4.3.0)"); }
void temp_fork() { strerr_die3x(111,"Unable to fork: ",error_str(errno),". (#4.3.0)"); }
void temp_read() { strerr_die3x(111,"Unable to read message: ",error_str(errno),". (#4.3.0)"); }
void temp_slowlock()
{ strerr_die1x(111,"File has been locked for 30 seconds straight. (#4.3.0)"); }
void temp_qmail(fn) const char *fn;
{ strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (#4.3.0)"); }

int flagdoit;
int flag99;

char *user;
char *homedir;
char *local;
char *dash;
char *ext;
char *host;
char *sender;
char *aliasempty;

/* define the global variables */
char *quotastring;

stralloc safeext = {0};
stralloc ufline = {0};
stralloc rpline = {0};
stralloc envrecip = {0};
stralloc dtline = {0};
stralloc qme = {0};
stralloc ueo = {0};
stralloc cmds = {0};
stralloc messline = {0};
stralloc foo = {0};
stralloc qapp = {0};

char buf[1024];
char outbuf[1024];

/* child process */
char fntmptph[80 + FMT_ULONG * 2];
char fnnewtph[83 + FMT_ULONG * 3];
void tryunlinktmp() { unlink(fntmptph); }
void sigalrm() { tryunlinktmp(); _exit(3); }
int msfd = -1; /* global filedescriptor to the quota file */

void maildir_child(dir)
char *dir;
{
 unsigned long pid;
 unsigned long tnow;
 char hostname[64];
 char *s;
 int loop;
 struct stat st;
 int fd;
 substdio ss;
 substdio ssout;

 sig_alarmcatch(sigalrm);
 if (chdir(dir) == -1) {
   if (error_temp(errno)) _exit(1); else _exit(2);
 }

 pid = getpid();
 hostname[0] = 0;
 gethostname(hostname,sizeof(hostname));
 for (loop = 0;;++loop)
  {
   tnow = now();
   s = fntmptph;
   s += fmt_str(s,"tmp/");
   s += fmt_ulong(s,tnow); *s++ = '.';
   s += fmt_ulong(s,pid); *s++ = '.';
   s += fmt_strn(s,hostname,sizeof(hostname)); 
   *s++ = 0;
   if (stat(fntmptph,&st) == -1) if (errno == error_noent) break;
   /* really should never get to this point */
   if (loop == 2) _exit(1);
   sleep(2);
  }
 str_copy(fnnewtph,fntmptph);
 byte_copy(fnnewtph,3,"new");

 alarm(86400);
 fd = open_excl(fntmptph);
 if (fd == -1) _exit(1);

 substdio_fdbuf(&ss,subread,0,buf,sizeof(buf));
 substdio_fdbuf(&ssout,subwrite,fd,outbuf,sizeof(outbuf));
 if (substdio_put(&ssout,rpline.s,rpline.len) == -1) goto fail;
 if (substdio_put(&ssout,dtline.s,dtline.len) == -1) goto fail;

 switch(substdio_copy(&ssout,&ss))
  {
   case -2: tryunlinktmp(); _exit(4);
   case -3: goto fail;
  }

 if (substdio_flush(&ssout) == -1) goto fail;
 if (fsync(fd) == -1) goto fail;
 if (fstat(fd, &st) == -1) goto fail;
 if (close(fd) == -1) goto fail; /* NFS dorks */

 s = fnnewtph;
 while( *s ) s++;
 s += fmt_str(s,",S=");
 s += fmt_ulong(s,(unsigned long) st.st_size);
 *s++ = 0;

 if( quotastring && *quotastring ) {
   /* finally update the quota file "maildirsize" */
   quota_add(msfd, (unsigned long) st.st_size, 1);
   close(msfd);
 }
  
 if (link(fntmptph,fnnewtph) == -1) goto fail;
   /* if it was error_exist, almost certainly successful; i hate NFS */
 tryunlinktmp(); _exit(0);

 fail: tryunlinktmp(); _exit(1);
}

/* end child process */

/* quota handling warning and bounce */
void quota_bounce(const char *type)
{
	strerr_die3x(100, "The users ", type,
	    " is over the allowed quota (size). (#5.2.2)");
}

void quota_warning(char *fn)
{
 int child;
 char *(args[3]);
 int wstat;

 if (!stralloc_copys(&qapp, auto_qmail)) temp_nomem();
 if (!stralloc_cats(&qapp, "/bin/qmail-quotawarn")) temp_nomem();
 if (!stralloc_0(&qapp)) temp_nomem();

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     args[0] = qapp.s; args[1] = fn; args[2] = 0;
     sig_pipedefault();
     execv(*args,args);
     _exit(2);
  }

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 2:
     strerr_die5x(111,"Unable to run quotawarn program: ",
	 qapp.s, ": ",error_str(errno),". (#4.2.2)");
   case 111: _exit(111);
   case 0: break;
   default: _exit(100);
  }

}
/* end -- quota handling warning and bounce */

void maildir(fn)
char *fn;
{
 int child;
 int wstat;

 /* quota handling maildir */
 struct stat mailst;
 int perc;
 quota_t q;
 unsigned long mailsize;

#ifdef AUTOMAILDIRMAKE
 switch (maildir_make(fn)) {
 case OK:
   break;
 case MAILDIR_CORRUPT:
   strerr_die3x(111,"The maildir '", fn, "' seems to be corrupted. (#4.2.1)");
 case ERRNO:
 default:
   strerr_die3x(111,"Unable to create maildir '", fn, "' (#4.3.0)");
 }
#endif

 if (quotastring && *quotastring) {
   if (fstat(0, &mailst) != 0)
       strerr_die3x(111,"Can not stat mail for quota: ",
	   error_str(errno),". (#4.3.0)");
   mailsize = mailst.st_size;
   quota_get(&q, quotastring);
   if (quota_calc(fn, &msfd, &q) == -1) {
     /* second chance */
     sleep(3);
     if (quota_calc(fn, &msfd, &q) == -1) {
       strerr_die1x(111,
	   "Temporary race condition while calculating quota. (#4.3.0)");
     }
   }
   /* fd can be -1 when retval = 0 quota_add/rm take care of that */
   
   if (quota_check(&q, mailsize, 1, &perc) != 0) { /* 0 if OK */
     if (quota_recalc(fn, &msfd, &q) == -1) {
       /* second chance */
       sleep(3);
       if (quota_recalc(fn, &msfd, &q) == -1)
	 strerr_die1x(111,
	     "Temporary race condition while recalculating quota. (#4.3.0)");
     }
     if (quota_check(&q, mailsize, 1, &perc) != 0) {
       /* bounce mail but drop a warning first */
       quota_warning(fn);
       quota_bounce("mailfolder");
     }
   }
   /* fd can be -1 when retval = 0 quota_add/rm take care of that */

   if (perc >= QUOTA_WARNING_LEVEL) 
     /* drop a warning when mailbox is around 80% full */
     quota_warning(fn);
 }
 
 /* end -- quota handling maildir */

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     maildir_child(fn);
     _exit(111);
  }

 if (msfd != -1) close(msfd); /* close the maildirsize fd in the parent */

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 0: break;
   case 2: strerr_die1x(111,"Unable to chdir to maildir. (#4.2.1)");
   case 3: strerr_die1x(111,"Timeout on maildir delivery. (#4.3.0)");
   case 4: strerr_die1x(111,"Unable to read message. (#4.3.0)");
   default: strerr_die1x(111,"Temporary error on maildir delivery. (#4.3.0)");
  }
}

void mailfile(fn)
char *fn;
{
 int fd;
 substdio ss;
 substdio ssout;
 int match;
 seek_pos pos;
 int flaglocked;

 /* quota handling mbox */
 struct stat filest, mailst;
 unsigned long totalsize;
 quota_t q;

 if( quotastring && *quotastring ) {
   quota_get(&q, quotastring);
   if (stat(fn, &filest) == -1) {
     filest.st_size = 0;        /* size of nonexisting mailfile */
     if ( errno != error_noent) { /* FALSE if file doesn't exist */
       strerr_die5x(111,"Unable to quota ", fn, ": ",error_str(errno), ". (#4.3.0)");
     }
   }
   if (fstat(0, &mailst) != 0)
     strerr_die3x(111,"Unable to quota mail: ",error_str(errno), ". (#4.3.0)");
   
   totalsize = (unsigned long) filest.st_size + (unsigned long) mailst.st_size;
   if (totalsize * 100 / q.quota_size >= QUOTA_WARNING_LEVEL)
     /* drop a warning when mailbox is around 80% full */
     quota_warning(fn);
   if (totalsize > q.quota_size)
     quota_bounce("mailbox");
 }
 
 /* end -- quota handling mbox */

 if (seek_begin(0) == -1) temp_rewind();

 fd = open_append(fn);
 if (fd == -1)
   strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (#4.2.1)");

 sig_alarmcatch(temp_slowlock);
 alarm(30);
 flaglocked = (lock_ex(fd) != -1);
 alarm(0);
 sig_alarmdefault();

 seek_end(fd);
 pos = seek_cur(fd);

 substdio_fdbuf(&ss,subread,0,buf,sizeof(buf));
 substdio_fdbuf(&ssout,subwrite,fd,outbuf,sizeof(outbuf));
 if (substdio_put(&ssout,ufline.s,ufline.len)) goto writeerrs;
 if (substdio_put(&ssout,rpline.s,rpline.len)) goto writeerrs;
 if (substdio_put(&ssout,dtline.s,dtline.len)) goto writeerrs;
 for (;;)
  {
   if (getln(&ss,&messline,&match,'\n') != 0) 
    {
     strerr_warn3("Unable to read message: ",error_str(errno),". (#4.3.0)",0);
     if (flaglocked) seek_trunc(fd,pos); close(fd);
     _exit(111);
    }
   if (!match && !messline.len) break;
   if (gfrom(messline.s,messline.len))
     if (substdio_bput(&ssout,">",1)) goto writeerrs;
   if (substdio_bput(&ssout,messline.s,messline.len)) goto writeerrs;
   if (!match)
    {
     if (substdio_bputs(&ssout,"\n")) goto writeerrs;
     break;
    }
  }
 if (substdio_bputs(&ssout,"\n")) goto writeerrs;
 if (substdio_flush(&ssout)) goto writeerrs;
 if (fsync(fd) == -1) goto writeerrs;
 close(fd);
 return;

 writeerrs:
 strerr_warn5("Unable to write ",fn,": ",error_str(errno),". (#4.3.0)",0);
 if (flaglocked) seek_trunc(fd,pos);
 close(fd);
 _exit(111);
}

void mailprogram(prog)
char *prog;
{
 int child;
 char *(args[4]);
 int wstat;

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     args[0] = (char *)"/bin/sh"; args[1] = (char *)"-c";
     args[2] = prog; args[3] = 0;
     sig_pipedefault();
     execv(*args,args);
     strerr_die3x(111,"Unable to run /bin/sh: ",error_str(errno),". (#4.3.0)");
  }

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 100:
   case 64: case 65: case 70: case 76: case 77: case 78: case 112: _exit(100);
   case 0: break;
   case 99: flag99 = 1; break;
   default: _exit(111);
  }
}

unsigned long mailforward_qp = 0;

void mailforward(recips)
char **recips;
{
 struct qmail qqt;
 const char *qqx;
 substdio ss;
 int match;

 if (seek_begin(0) == -1) temp_rewind();
 substdio_fdbuf(&ss,subread,0,buf,sizeof(buf));

 if (qmail_open(&qqt) == -1) temp_fork();
 mailforward_qp = qmail_qp(&qqt);

 qmail_put(&qqt,dtline.s,dtline.len);

 if (recips[1])
   qmail_puts(&qqt,"Precedence: bulk\n");

 do
  {
   if (getln(&ss,&messline,&match,'\n') != 0) { qmail_fail(&qqt); break; }
   qmail_put(&qqt,messline.s,messline.len);
  }
 while (match);
 qmail_from(&qqt,ueo.s);
 while (*recips) qmail_to(&qqt,*recips++);
 qqx = qmail_close(&qqt);
 if (!*qqx) return;
 strerr_die3x(*qqx == 'D' ? 100 : 111,"Unable to forward message: ",qqx + 1,".");
}

void bouncexf()
{
 int match;
 substdio ss;

 if (seek_begin(0) == -1) temp_rewind();
 substdio_fdbuf(&ss,subread,0,buf,sizeof(buf));
 for (;;)
  {
   if (getln(&ss,&messline,&match,'\n') != 0) temp_read();
   if (!match) break;
   if (messline.len <= 1)
     break;
   if (messline.len == dtline.len)
     if (!str_diffn(messline.s,dtline.s,dtline.len))
       strerr_die1x(100,"This message is looping: it already has my Delivered-To line. (#5.4.6)");
  }
}

void checkhome()
{
 struct stat st;

 if (stat(".",&st) == -1)
   strerr_die3x(111,"Unable to stat home directory: ",error_str(errno),". (#4.3.0)");
 if (st.st_mode & auto_patrn)
   strerr_die1x(111,"Uh-oh: home directory is writable. (#4.7.0)");
 if (st.st_mode & 01000) {
   if (flagdoit)
     strerr_die1x(111,"Home directory is sticky: user is editing his .qmail file. (#4.2.1)");
   else
     strerr_warn1("Warning: home directory is sticky.",0);
 }
}

int qmeox(dashowner)
char *dashowner;
{
 struct stat st;

 if (!stralloc_copys(&qme,".qmail")) temp_nomem();
 if (!stralloc_cats(&qme,dash)) temp_nomem();
 if (!stralloc_cat(&qme,&safeext)) temp_nomem();
 if (!stralloc_cats(&qme,dashowner)) temp_nomem();
 if (!stralloc_0(&qme)) temp_nomem();
 if (stat(qme.s,&st) == -1)
  {
   if (error_temp(errno)) temp_qmail(qme.s);
   return -1;
  }
 return 0;
}

int qmeexists(fd,cutable)
int *fd;
int *cutable;
{
  struct stat st;

  if (!stralloc_0(&qme)) temp_nomem();

  *fd = open_read(qme.s);
  if (*fd == -1) {
    if (error_temp(errno)) temp_qmail(qme.s);
    if (errno == error_perm) temp_qmail(qme.s);
    if (errno == error_acces) temp_qmail(qme.s);
    return 0;
  }

  if (fstat(*fd,&st) == -1) temp_qmail(qme.s);
  if ((st.st_mode & S_IFMT) == S_IFREG) {
    if (st.st_mode & auto_patrn)
      strerr_die1x(111,"Uh-oh: .qmail file is writable. (#4.7.0)");
    *cutable = !!(st.st_mode & 0100);
    return 1;
  }
  close(*fd);
  return 0;
}

/* "" "": "" */
/* "-/" "": "-/" "-/default" */
/* "-/" "a": "-/a" "-/default" */
/* "-/" "a-": "-/a-" "-/a-default" "-/default" */
/* "-/" "a-b": "-/a-b" "-/a-default" "-/default" */
/* "-/" "a-b-": "-/a-b-" "-/a-b-default" "-/a-default" "-/default" */
/* "-/" "a-b-c": "-/a-b-c" "-/a-b-default" "-/a-default" "-/default" */

void qmesearch(fd,cutable)
int *fd;
int *cutable;
{
  unsigned int i;

  if (!stralloc_copys(&qme,".qmail")) temp_nomem();
  if (!stralloc_cats(&qme,dash)) temp_nomem();
  if (!stralloc_cat(&qme,&safeext)) temp_nomem();
  if (qmeexists(fd,cutable)) {
    if (safeext.len >= 7) {
      i = safeext.len - 7;
      if (!byte_diff("default",7,safeext.s + i))
	if (i <= str_len(ext)) /* paranoia */
	  if (!env_put2("DEFAULT",ext + i)) temp_nomem();
    }
    return;
  }

  i = safeext.len;
  do {
    if (!i || (safeext.s[i - 1] == '-')) {
      if (!stralloc_copys(&qme,".qmail")) temp_nomem();
      if (!stralloc_cats(&qme,dash)) temp_nomem();
      if (!stralloc_catb(&qme,safeext.s,i)) temp_nomem();
      if (!stralloc_cats(&qme,"default")) temp_nomem();
      if (qmeexists(fd,cutable)) {
	if (i <= str_len(ext)) /* paranoia */
	  if (!env_put2("DEFAULT",ext + i)) temp_nomem();
        return;
      }
    }
  } while (i-- != 0);

  *fd = -1;
}

unsigned long count_file = 0;
unsigned long count_forward = 0;
unsigned long count_program = 0;
char count_buf[FMT_ULONG];

void count_print()
{
 substdio_puts(subfdoutsmall,"did ");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_file));
 substdio_puts(subfdoutsmall,"+");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_forward));
 substdio_puts(subfdoutsmall,"+");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_program));
 substdio_puts(subfdoutsmall,"\n");
 if (mailforward_qp)
  {
   substdio_puts(subfdoutsmall,"qp ");
   substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,mailforward_qp));
   substdio_puts(subfdoutsmall,"\n");
  }
 substdio_flush(subfdoutsmall);
}

void sayit(type,cmd,len)
char *type;
char *cmd;
unsigned int len;
{
 substdio_puts(subfdoutsmall,type);
 substdio_put(subfdoutsmall,cmd,len);
 substdio_putsflush(subfdoutsmall,"\n");
}

void unescape(char *s)
{
  if (!stralloc_copys(&foo, "")) temp_nomem();
  do {
    if (s[0] == '\\' && s[1] == ':') s++;
    else if (s[0] == ':') {
      if (!stralloc_0(&foo)) temp_nomem();
      continue;
    }
    if (!stralloc_append(&foo, s)) temp_nomem();
  } while (*s++);
}

int main(argc,argv)
int argc;
char **argv;
{
 int opt;
 unsigned int i;
 unsigned int j;
 unsigned int k;
 int fd;
 unsigned int numforward;
 char **recips;
 datetime_sec starttime;
 int flagforwardonly;
 char *x;

 /* set up the variables for qmail-ldap */
 unsigned int slen;
 int qmode;
 int flagforwardonly2;
 int flagnoforward;
 int flagnolocal;
 int flagnoprog;
 int allowldapprog;
 char *s;
 char *rt;

 umask(077);
 sig_pipeignore();

 if (!env_init()) temp_nomem();

 flagdoit = 1;
 while ((opt = getopt(argc,argv,"nN")) != opteof)
   switch(opt)
    {
     case 'n': flagdoit = 0; break;
     case 'N': flagdoit = 1; break;
     default:
       usage();
    }
 argc -= optind;
 argv += optind;

 if (!(user = *argv++)) usage();
 if (!(homedir = *argv++)) usage();
 if (!(local = *argv++)) usage();
 if (!(dash = *argv++)) usage();
 if (!(ext = *argv++)) usage();
 if (!(host = *argv++)) usage();
 if (!(sender = *argv++)) usage();
 if (!(aliasempty = *argv++)) usage();
 if (*argv) usage();

 if (homedir[0] != '/') usage();
 if (chdir(homedir) == -1)
   strerr_die5x(111,"Unable to switch to ",homedir,": ",error_str(errno),". (#4.3.0)");
 checkhome();

 if (!env_put2("HOST",host)) temp_nomem();
 if (!env_put2("HOME",homedir)) temp_nomem();
 if (!env_put2("USER",user)) temp_nomem();
 if (!env_put2("LOCAL",local)) temp_nomem();

 if (!stralloc_copys(&envrecip,local)) temp_nomem();
 if (!stralloc_cats(&envrecip,"@")) temp_nomem();
 if (!stralloc_cats(&envrecip,host)) temp_nomem();

 if (!stralloc_copy(&foo,&envrecip)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("RECIPIENT",foo.s)) temp_nomem();

 if (!stralloc_copys(&dtline,"Delivered-To: ")) temp_nomem();
 if (!stralloc_cat(&dtline,&envrecip)) temp_nomem();
 for (i = 0;i < dtline.len;++i) if (dtline.s[i] == '\n') dtline.s[i] = '_';
 if (!stralloc_cats(&dtline,"\n")) temp_nomem();

 if (!stralloc_copy(&foo,&dtline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("DTLINE",foo.s)) temp_nomem();

 if (flagdoit)
   bouncexf();

 if (!env_put2("SENDER",sender)) temp_nomem();

 if (!quote2(&foo,sender)) temp_nomem();
 if (!stralloc_copys(&rpline,"Return-Path: <")) temp_nomem();
 if (!stralloc_cat(&rpline,&foo)) temp_nomem();
 for (i = 0;i < rpline.len;++i) if (rpline.s[i] == '\n') rpline.s[i] = '_';
 if (!stralloc_cats(&rpline,">\n")) temp_nomem();

 if (!stralloc_copy(&foo,&rpline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("RPLINE",foo.s)) temp_nomem();

 if (!stralloc_copys(&ufline,"From ")) temp_nomem();
 if (*sender)
  {
   unsigned int len; char ch;

   len = str_len(sender);
   if (!stralloc_readyplus(&ufline,len)) temp_nomem();
   for (i = 0;i < len;++i)
    {
     ch = sender[i];
     if ((ch == ' ') || (ch == '\t') || (ch == '\n')) ch = '-';
     ufline.s[ufline.len + i] = ch;
    }
   ufline.len += len;
  }
 else
   if (!stralloc_cats(&ufline,"MAILER-DAEMON")) temp_nomem();
 if (!stralloc_cats(&ufline," ")) temp_nomem();
 starttime = now();
 if (!stralloc_cats(&ufline,myctime(starttime))) temp_nomem();

 if (!stralloc_copy(&foo,&ufline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("UFLINE",foo.s)) temp_nomem();

 x = ext;
 if (!env_put2("EXT",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT2",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT3",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT4",x)) temp_nomem();

 if (!stralloc_copys(&safeext,ext)) temp_nomem();
 case_lowerb(safeext.s,safeext.len);
 for (i = 0;i < safeext.len;++i)
   if (safeext.s[i] == '.')
     safeext.s[i] = ':';

 i = str_len(host);
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST2",foo.s)) temp_nomem();
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST3",foo.s)) temp_nomem();
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST4",foo.s)) temp_nomem();

 flagforwardonly = 0; flagforwardonly2 = 0; allowldapprog = 0;
 flagnoforward = 0; flagnolocal = 0; flagnoprog = 0;

 if (env_get(ENV_GROUP)) {
   if (flagdoit) {
     ++count_program;
     if (!stralloc_copys(&foo,"qmail-group ")) temp_nomem();
     if (*aliasempty == '.' || *aliasempty == '/')
       if (!stralloc_cats(&foo,aliasempty)) temp_nomem();
     if (!stralloc_0(&foo)) temp_nomem();
     mailprogram(foo.s);
   } else
     sayit("group delivery","",0);
   count_print();
   _exit(0);
 }
 /* quota, dotmode and forwarding handling - part 1 */
 /* setting the quota */
 if ((quotastring = env_get(ENV_QUOTA) ) && *quotastring) {
   if (!flagdoit) sayit("quota defined as: ",quotastring,str_len(quotastring));
 } else {
   if (!flagdoit) sayit("unlimited quota",quotastring,0 );
 }
   
 qmode = DO_DOT;  /* default is to use standard .qmail */
 if ((s = env_get(ENV_DOTMODE))) {
   if (!case_diffs(DOTMODE_LDAPONLY, s)) {
     if (!flagdoit) sayit("DOTMODE_LDAPONLY ",s,0);
     qmode = DO_LDAP;
   } else if (!case_diffs(DOTMODE_LDAPWITHPROG, s)) {
     if (!flagdoit) sayit("DOTMODE_LDAPWITHPROG ",s,0);
     qmode = DO_LDAP;
     allowldapprog = 1;
   } else if (!case_diffs(DOTMODE_DOTONLY, s)) {
     if (!flagdoit) sayit("DOTMODE_DOTONLY ",s,0);
     qmode = DO_DOT;
   } else if (!case_diffs(DOTMODE_BOTH, s)) {
     if (!flagdoit) sayit("DOTMODE_BOTH ",s,0);
     qmode = DO_BOTH;
     allowldapprog = 1;
   } else
     strerr_die3x(100,"Error: Non valid dot-mode found: ", s, ". (#5.3.5)");
 }
	   
 /* prepare the cmds string to hold all the commands from the 
  * ldap server and the .qmail file */
 if (!stralloc_ready(&cmds,0)) temp_nomem();
 cmds.len = 0;
 
 if (qmode & DO_LDAP) {
   /* get the infos from the ldap server (environment) */
   /* setting the NEWSENDER so echo and forward will work */
   if (!stralloc_copys(&ueo,sender)) temp_nomem();
   if (!stralloc_0(&ueo)) temp_nomem();
   if (!env_put2("NEWSENDER",ueo.s)) temp_nomem();

   if ((s = env_get(ENV_MODE))) {
     unescape(s);
     s = foo.s;
     slen = foo.len-1;
     for(;;) {
       if (!case_diffs(MODE_FONLY, s)) {
         if (!flagdoit) sayit("force forward only ",s,0);
         flagforwardonly2 = 1;
         flagnolocal = 1;
         flagnoprog = 1;
       } else if (!case_diffs(MODE_REPLY, s)) {
         if(*sender) {
           if ((rt = env_get(ENV_REPLYTEXT))) {
	     ++count_forward;
             if (flagdoit) {
	       if (!stralloc_copys(&qapp,"qmail-reply ")) temp_nomem();
	       if (*aliasempty == '.' || *aliasempty == '/')
	         if (!stralloc_cats(&qapp,aliasempty)) temp_nomem();
	       if (!stralloc_0(&qapp)) temp_nomem();
               mailprogram(qapp.s);
             } else {
               sayit("reply to ",sender,str_len(sender));
               sayit("replytext ",rt,str_len(rt));
             }
           } else {
             strerr_warn1("Warning: Reply mode is on but there is no reply text.", 0);
           }
         }
       } else if (!case_diffs(MODE_NOLOCAL, s) || !case_diffs(MODE_NOMBOX, s)) {
         if (!flagdoit) sayit("no file delivery ",s,0);
         flagnolocal = 1;
       } else if (!case_diffs(MODE_NOFORWARD, s)) {
	 if (!flagdoit) sayit("no mail forwarding ",s,0);
	 flagnoforward = 1;
       } else if (!case_diffs(MODE_NOPROG, s)) {
         if (!flagdoit) sayit("no program delivery ",s,0);
         flagnoprog = 1;
       } else if (!case_diffs(MODE_LOCAL, s) ||
		  !case_diffs(MODE_FORWARD, s) ||
		  !case_diffs(MODE_PROG, s) ||
		  !case_diffs(MODE_NOREPLY, s)) {
	       /* ignore */;
       } else strerr_warn3("Warning: undefined mail delivery mode: ",
                     s," (ignored).", 0);
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }
   if (allowldapprog && !flagnoprog && (s = env_get(ENV_PROGRAM))) {
     unescape(s);
     s = foo.s;
     slen = foo.len-1;
     for (;;) {
       if (!stralloc_cats(&cmds, "|")) temp_nomem();
       if (!stralloc_cats(&cmds, s)) temp_nomem();
       if (!stralloc_cats(&cmds, "\n")) temp_nomem();
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }
   if (!flagnoforward && (s = env_get(ENV_FORWARDS))) {
     unescape(s);
     s = foo.s;
     slen = foo.len-1;
     for (;;) {
       if (!stralloc_cats(&cmds, "&")) temp_nomem();
       if (!stralloc_cats(&cmds, s)) temp_nomem();
       if (!stralloc_cats(&cmds, "\n")) temp_nomem();
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }
   if (!flagnolocal) {
     if (!stralloc_cats(&cmds,aliasempty)) temp_nomem();
     if (!stralloc_cats(&cmds, "\n")) temp_nomem();
   } 
   if (!stralloc_cats(&cmds, "#\n")) temp_nomem();
 } 
 if (qmode & DO_DOT) { /* start dotqmail */
   qmesearch(&fd,&flagforwardonly);
   if (fd == -1)
     if (*dash)
       if (qmode == DO_DOT) /* XXX: OK ??? */
         strerr_die1x(100,"Sorry, no mailbox here by that name. (#5.1.1)");

   if (!stralloc_copys(&ueo,sender)) temp_nomem();
   if (str_diff(sender,""))
     if (str_diff(sender,"#@[]"))
       if (qmeox("-owner") == 0) {
         if (qmeox("-owner-default") == 0) {
           if (!stralloc_copys(&ueo,local)) temp_nomem();
           if (!stralloc_cats(&ueo,"-owner-@")) temp_nomem();
           if (!stralloc_cats(&ueo,host)) temp_nomem();
           if (!stralloc_cats(&ueo,"-@[]")) temp_nomem();
         } else {
           if (!stralloc_copys(&ueo,local)) temp_nomem();
           if (!stralloc_cats(&ueo,"-owner@")) temp_nomem();
           if (!stralloc_cats(&ueo,host)) temp_nomem();
         }
       }
 
   if (!stralloc_0(&ueo)) temp_nomem();
   if (!env_put2("NEWSENDER",ueo.s)) temp_nomem();

   if (fd != -1)
     if (slurpclose(fd,&cmds,256) == -1) temp_nomem();

 } else if (!qmode & DO_LDAP) /* impossible see dotmode handling */
   strerr_die1x(100,"Error: No valid delivery mode selected. (#5.3.5)");

 if (!cmds.len)
  {
   if (!stralloc_copys(&cmds,aliasempty)) temp_nomem();
   flagforwardonly = 0;
  }
 if (!cmds.len || (cmds.s[cmds.len - 1] != '\n'))
   if (!stralloc_cats(&cmds,"\n")) temp_nomem();

 numforward = 0;
 i = 0;
 for (j = 0;j < cmds.len;++j)
   if (cmds.s[j] == '\n')
    {
     switch(cmds.s[i]) { case '#': case '.': case '/': case '|': break;
       default: ++numforward; }
     i = j + 1;
    }

 if (flagnoforward) numforward = 0;
 
 recips = (char **) alloc((numforward + 1) * sizeof(char *));
 if (!recips) temp_nomem();
 numforward = 0;

 flag99 = 0;

 i = 0;
 for (j = 0;j < cmds.len;++j)
   if (cmds.s[j] == '\n')
    {
     cmds.s[j] = 0;
     k = j;
     while ((k > i) && ((cmds.s[k - 1] == ' ') || (cmds.s[k - 1] == '\t')))
       cmds.s[--k] = 0;
     switch(cmds.s[i])
      {
       case 0: /* k == i */
	 if (i) break;
         strerr_die1x(111,"Uh-oh: first line of .qmail file is blank. (#4.2.1)");
       case '#':
         break;
       case '.':
       case '/':
	 if (flagnolocal) {
	   if (flagdoit) break;
	   else { sayit("disabled file delivery ", cmds.s + i, k - i); break; }
	 }
	 ++count_file;
	 if (flagforwardonly) strerr_die1x(111,"Uh-oh: .qmail has file delivery but has x bit set. (#4.7.0)");
	 if (flagforwardonly2) 
	   strerr_die1x(111,"Uh-oh: user has file delivery but is not allowed to. (#4.7.0)");
	 if (cmds.s[k - 1] == '/')
           if (flagdoit) maildir(cmds.s + i);
           else sayit("maildir ",cmds.s + i,k - i);
	 else
           if (flagdoit) mailfile(cmds.s + i);
           else sayit("mbox ",cmds.s + i,k - i);
         break;
       case '|':
	 if (flagnoprog) {
	   if (flagdoit) break;
	   else { sayit("disabled program ", cmds.s + i, k - i); break; }
	 }
	 ++count_program;
	 if (flagforwardonly) strerr_die1x(111,"Uh-oh: .qmail has prog delivery but has x bit set. (#4.7.0)");
	 if (flagforwardonly2)
	   strerr_die1x(111,"Uh-oh: user has prog delivery but is not allowed to. (#4.7.0)");
         if (flagdoit) mailprogram(cmds.s + i + 1);
         else sayit("program ",cmds.s + i + 1,k - i - 1);
         break;
       case '+':
	 if (str_equal(cmds.s + i + 1,"list"))
	   flagforwardonly = 1;
	 break;
       case '&':
         ++i;
       default:
	 ++count_forward;
	 if (flagnoforward) {
	   if (flagdoit) break;
	   else { sayit("disabled forward ", cmds.s + i, k - i); break; }
	 }
         if (flagdoit) recips[numforward++] = cmds.s + i;
         else sayit("forward ",cmds.s + i,k - i);
         break;
      }
     i = j + 1;
     if (flag99) break;
    }

 if (numforward) if (flagdoit) if (!flagnoforward)
  {
   recips[numforward] = 0;
   mailforward(recips);
  }

 count_print();
 return 0;
}
