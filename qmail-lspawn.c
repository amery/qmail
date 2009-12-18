#include "fd.h"
#include "wait.h"
#include "prot.h"
#include "substdio.h"
#include "stralloc.h"
#include "scan.h"
#include "exit.h"
#include "fork.h"
#include "error.h"
#include "cdb.h"
#include "case.h"
#include "slurpclose.h"
#include "auto_qmail.h"
#include "auto_uids.h"
#include "qlx.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include "auto_break.h"
#include "auto_usera.h"
#include "byte.h"
#include "check.h"
#include "env.h"
#include "fmt.h"
#include "localdelivery.h"
#include "open.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "qmail-ldap.h"
#include "read-ctrl.h"
#include "sig.h"
#include "str.h"
#ifdef QLDAP_CLUSTER
#include "qldap-cluster.h"
#include "getln.h"
#include "seek.h"
#endif
#ifdef AUTOHOMEDIRMAKE
#include "dirmaker.h"
#endif

const char *aliasempty;

#ifdef QLDAP_CLUSTER
/* declaration of the mail forwarder function */
void forward_mail(char *, char *, char *, int , int);
#endif

#ifdef AUTOHOMEDIRMAKE
void check_home(const char *home, const char *maildir)
{
  struct stat	st;

  if (stat(home, &st) == 0) return;
  if (errno == error_noent)
    switch (dirmaker_make(home, maildir)) {
    case 0:
      break;
    case ERRNO:
     if (error_temp(errno)) _exit(QLX_DIRMAKESOFT);
     _exit(QLX_DIRMAKEHARD);
    case MAILDIR_CRASHED:
      _exit(QLX_DIRMAKECRASH);
    case MAILDIR_HARD:
      _exit(QLX_DIRMAKEHARD);
    case MAILDIR_UNCONF:
      /* qmail-local will return a nice error */
      break;
    default:
      _exit(QLX_DIRMAKESOFT);
    }
}
#endif

ctrlfunc ctrls[] = {
  qldap_ctrl_login,
  qldap_ctrl_generic,
  localdelivery_init,
#ifdef QLDAP_CLUSTER
  cluster_init,
#endif
#ifdef AUTOHOMEDIRMAKE
  dirmaker_init,
#endif		
  0
};

/* here it is not possible to log something */
void initialize(argc,argv)
int argc;
char **argv;
{
   aliasempty = argv[1];
   if (!aliasempty) {
      _exit(100);
   }
   
  if (read_controls(ctrls) == -1)
    _exit(QLX_USAGE);

}

unsigned int truncreport = 3000;

void report(ss,wstat,s,len)
substdio *ss;
int wstat;
char *s;
unsigned int len;
{
   unsigned int i;
   if (wait_crashed(wstat)) {
      substdio_puts(ss,"Zqmail-local crashed.\n");
      return;
   }
   switch(wait_exitcode(wstat)) {
   case QLX_CDB:
     substdio_puts(ss,"ZTrouble reading users/cdb in qmail-lspawn.\n");
     return;
   case QLX_NOMEM:
     substdio_puts(ss,"ZOut of memory in qmail-lspawn.\n");
     return;
   case QLX_SYS:
     substdio_puts(ss,"ZTemporary failure in qmail-lspawn.\n");
     return;
   case QLX_NOALIAS:
     substdio_puts(ss,"ZUnable to find alias user!\n");
     return;
   case QLX_ROOT:
     substdio_puts(ss,"ZNot allowed to perform deliveries as root.\n");
     return;
   case QLX_USAGE:
     substdio_puts(ss,"ZInternal qmail-lspawn bug.\n");
     return;
   case QLX_NFS:
     substdio_puts(ss,"ZNFS failure in qmail-local.\n");
     return;
   case QLX_EXECHARD:
     substdio_puts(ss,"DUnable to run qmail-local.\n");
     return;
   case QLX_EXECSOFT:
     substdio_puts(ss,"ZUnable to run qmail-local.\n");
     return;
   case QLX_EXECPW:
     substdio_puts(ss,"ZUnable to run qmail-getpw.\n");
     return;
   case 111: case 71: case 74: case 75:
     substdio_put(ss,"Z",1);
     break;
   case 0:
     substdio_put(ss,"K",1);
     break;
      
   /* report LDAP errors */
   case QLX_DISABLED:
     substdio_puts(ss, "DMailaddress is administratively disabled. (#5.2.1)\n");
     return;
   case QLX_DELETED:
     substdio_puts(ss, "DSorry, no mailbox here by that name. (#5.1.1)\n");
     return;
   case QLX_MAXSIZE:
     substdio_puts(ss, "DThe message exeeded the maximum size the user accepts. (#5.2.3)\n");
     return;
   case QLX_LDAPFAIL:
     substdio_puts(ss, "ZTemporary failure in LDAP lookup. (#4.4.3).\n");
     return;
   case QLX_LDAPAUTH:
     substdio_puts(ss, "ZUnable to login into LDAP server, bad credentials. (#4.4.3)\n");
     return;
   case QLX_SEARCHTIMEOUT:
     substdio_puts(ss, "ZTimeout while performing search on LDAP server. (#4.4.3)");
     return;
   case QLX_BINDTIMEOUT:
     substdio_puts(ss, "ZUnable to contact LDAP server. (#4.4.3)");
     return;
   case QLX_TOOMANY:
     substdio_puts(ss, "DToo many results returned but needs to be unique. (#5.3.5)\n");
     return;
   case QLX_NEEDED:
     substdio_puts(ss, "DLDAP attribute is not given but mandatory. (#5.3.5)\n");
     return;
   case QLX_ILLVAL:
     substdio_puts(ss, "DIllegal value in LDAP attribute. (#5.3.5)\n");
     return;
#ifdef QLDAP_CLUSTER
   case QLX_CLUSTERSOFT:
     substdio_puts(ss, "ZTemporary error while executing qmail-forward. (#4.4.4)\n");
     return;
   case QLX_CLUSTERHARD:
     substdio_puts(ss, "DPermanent error while executing qmail-forward. (#5.4.4)\n");
     return;
#endif /* QLDAP_CLUSTER */
#ifdef AUTOHOMEDIRMAKE
   case QLX_DIRMAKECRASH:
     substdio_puts(ss, "ZAutomatic homedir creator crashed (#4.3.0)\n");
     return;
   case QLX_DIRMAKESOFT:
     substdio_puts(ss, "ZTemporary error in automatic homedir creation. (#4.3.0)\n");
     return;
   case QLX_DIRMAKEHARD:
     substdio_puts(ss, "DPermanent error in automatic homedir creation. (#5.3.0)\n");
     return;
#endif

   case 100:
   default:
     substdio_put(ss,"D",1);
     break;
  }

  for (i = 0;i < len;++i) if (!s[i]) break;
  substdio_put(ss,s,i);
}

stralloc nughde = {0};
stralloc host = {0};
stralloc user = {0};
stralloc homedir = {0};
stralloc maildir = {0};
stralloc foo = {0}; /* stralloc for temporary stuff */

/* LDAP server query routines */

void cae(qldap *q, int n)
{
  qldap_free(q);
  _exit(n);
}

int qldap_get(stralloc *mail, unsigned int at, int fdmess)
{
   const char *attrs[] = {  /* LDAP_MAIL, */ /* not needed */
                      /* LDAP_MAILALTERNATE, */
                      LDAP_UID,
                      LDAP_QMAILUID,
                      LDAP_QMAILGID,
                      LDAP_ISACTIVE,
                      LDAP_MAILHOST,
                      LDAP_MAILSTORE,
                      LDAP_HOMEDIR,
		      LDAP_QUOTA_SIZE,
		      LDAP_QUOTA_COUNT,
                      LDAP_FORWARDS,
                      LDAP_PROGRAM,
                      LDAP_MODE,
                      LDAP_REPLYTEXT,
                      LDAP_DOTMODE, 
		      LDAP_MAXMSIZE,
		      LDAP_OBJECTCLASS, 0};
   char num[FMT_ULONG];
   char *f;
   struct passwd *pw;
   struct qldap *q;
   struct stat st;
   unsigned long count;
   unsigned long maxsize;
   unsigned long size;
   unsigned int len;
   unsigned int id;
   int done;
   int status;
   int rv;

   /* TODO more debug output is needed */
   q = qldap_new();
   if (q == 0)
     _exit(QLX_NOMEM);

   rv = qldap_open(q);
   if (rv != OK) goto fail;
   rv = qldap_bind(q, 0, 0);
   if (rv != OK) goto fail;

   /*
    * this handles the "catch all" and "-default" extension 
    * but also the normal eMail address.
    * Code handels also mail addresses with multiple '@' safely.
    * at = index to last @ sign in mail address
    * escaped = ldap escaped mailaddress
    * len = length of escaped mailaddress
    * i = position of current '-' or '@'
    */
   done = 0;
   do {
     f = filter_mail(mail->s, &done);
     if (f == (char *)0) cae(q, QLX_NOMEM);
     
     logit(16, "ldapfilter: '%s'\n", f);
  
     /* do the search for the email address */
     rv = qldap_lookup(q, f, attrs);
     switch (rv) {
     case OK:
       break; /* something found */
     case TIMEOUT:
       /* don't try an other address, retry later, hopefully ... */
       cae(q, QLX_SEARCHTIMEOUT);
     case TOOMANY:
#ifdef DUPEALIAS
       /*
        * we are going to deliver this to a special alias user for
        * further processing
        */
       qldap_free(q);
       return 3;
#else
       /* admin error, don't try a lower precedence addresses */
       cae(q, QLX_TOOMANY);
#endif
     case FAILED:
       /* ... again do not retry lower precedence addresses */
       cae(q, QLX_LDAPFAIL);
     case NOSUCH:
       break;
     }
   } while (rv != OK && !done);

   /* nothing found, try a local lookup or a alias delivery */
   if (rv == NOSUCH) {
     qldap_free(q);
     return 1;
   }

   
   /*
    * Search was successful.
    * Now go through the attributes and set the proper args for qmail-local.
    * But first check account status, the mail size and forward the message
    * to the correct cluster host if needed.
    *
    */

   
   /* check if the ldap entry is active */
   rv = qldap_get_status(q, &status);
   if (rv != OK) goto fail;
   if (status == STATUS_BOUNCE) {
     logit(2, "warning: %s's account status is bounce\n", mail->s);
     cae(q, QLX_DISABLED); 
   } else if (status == STATUS_DELETE) {
     logit(2, "warning: %s's account status is deleted\n", mail->s);
     cae(q, QLX_DELETED); 
   }

   /* get the quota for the user of that maildir mbox */
   rv = qldap_get_quota(q, &size, &count, &maxsize);
   if (rv != OK) goto fail;
   /* check if incomming mail is smaller than max mail size */
   if (maxsize != 0) {
     if (fstat(fdmess, &st) != 0) {
       logit(2, "warning: can not stat mail: %s\n", error_str(errno));
       cae(q, QLX_SYS);
     }
     if ((unsigned long)st.st_size > maxsize) {
       cae(q, QLX_MAXSIZE);
     }
   }
  
#ifdef QLDAP_CLUSTER
   rv = qldap_get_attr(q, LDAP_MAILHOST, &host, SINGLE_VALUE);
   if (rv != OK && rv != NOSUCH) goto fail;

   /* check if the I'm the right host */
   if (rv == OK && cluster(host.s) == 1) {
     logit(8, "cluster: forwarding session to %s\n", host.s);
     /* hostname is different, so I reconnect */
     return 2;
   }
#endif

   /* get the path of the maildir or mbox */
   rv = qldap_get_mailstore(q, &homedir, &maildir);
   switch (rv) {
   case OK:
     if (maildir.len > 0)
       aliasempty = maildir.s;
     break;
   case NEEDED:
     /*
      * nothing defined use alias user for delivery and 
      * ALIASDEVNULL as aliasempty
      */
     logit(32, "forward only delivery via alias user\n");
     pw = getpwnam(auto_usera);
     if (!pw) cae(q, QLX_NOALIAS);
     if (!stralloc_copys(&nughde, pw->pw_name)) cae(q, QLX_NOMEM);
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_uid))) 
       cae(q, QLX_NOMEM);
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_gid))) 
       cae(q, QLX_NOMEM);
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     if (!stralloc_cats(&nughde, pw->pw_dir)) cae(q, QLX_NOMEM); 
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     if (!stralloc_cats(&nughde, "-")) cae(q, QLX_NOMEM);
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     if (!stralloc_catb(&nughde, mail->s, at)) cae(q, QLX_NOMEM);
     if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
     aliasempty = ALIASDEVNULL;
     /* get the forwarding addresses */
     rv = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
     if (rv != OK) goto fail;
     if (!env_put2(ENV_FORWARDS, foo.s)) cae(q, QLX_NOMEM);
     logit(32, "%s: %s\n", ENV_FORWARDS, foo.s);
     /* setup strict env */
     if (!env_put2(ENV_DOTMODE, DOTMODE_LDAPONLY)) _exit(QLX_NOMEM);
     if (!env_put2(ENV_MODE, MODE_FONLY)) _exit(QLX_NOMEM);
     qldap_free(q);
     return 0;
   default:
     goto fail;
   }

   /* get the user name */
   rv = qldap_get_user(q, &user);
   if (rv != OK) goto fail;
   if (!stralloc_copy(&nughde, &user)) _exit(QLX_NOMEM);

   /* get the UID for delivery on the local system */
   rv = qldap_get_uid(q, &id);
   if (rv != OK) goto fail;
   if (!stralloc_catb(&nughde,num,fmt_uint(num, id))) 
     cae(q, QLX_NOMEM);
   if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);

   
   /* get the GID for delivery on the local system */
   rv = qldap_get_gid(q, &id);
   if (rv != OK) goto fail;
   if (!stralloc_catb(&nughde,num,fmt_uint(num, id))) 
     cae(q, QLX_NOMEM);
   if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);

   /* homedir saved earlier */
   if (!stralloc_cat(&nughde, &homedir)) cae(q, QLX_NOMEM);

   /*
    *  Fill up the dash-field and the extension field with the values
    * used for the dash-ext search.
    */
   rv = filter_mail_ext();
   if (rv != -1)
     if (!stralloc_cats(&nughde,"-")) cae(q, QLX_NOMEM);
   if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);
   if (rv != -1) {
     unsigned int ext;
     int i;
     for (ext = 0, i = 0; i < rv && ext < at; ext++)
       if (mail->s[ext] == *auto_break) i++;
     if (!stralloc_catb(&nughde, mail->s+ext,at-ext)) cae(q, QLX_NOMEM);
   }
   if (!stralloc_0(&nughde)) cae(q, QLX_NOMEM);

   /*
    * nughde is filled now setup the environment, with:
    * quota string (already done while checking mail size)
    * mail group handling
    * mail forwarders
    * delivery programs
    * reply text
    * delivery mode
    * dot mode
    */

   rv = qldap_get_attr(q, LDAP_OBJECTCLASS, &foo, MULTI_VALUE);
   if (rv != OK) goto fail; /* objectclass is a must */
   if (!env_unset(ENV_GROUP)) cae(q, QLX_NOMEM);
   for (len = 0; len < foo.len;
        len += byte_chr(foo.s + len, foo.len - len, ':') + 1) {
     if (case_startb(foo.s + len, foo.len - len, LDAP_GROUPOBJECTCLASS)) {
       rv = qldap_get_dn(q, &foo);
       if (rv != OK) goto fail;
       logit(32, "%s: %s\n", ENV_GROUP, foo.s);
       if (!env_put2(ENV_GROUP, foo.s )) cae(q, QLX_NOMEM);
       break;
     }
   }

   /*
    * set the quota environment
    */
   if (size != 0 || count != 0) {
     if (!stralloc_copys(&foo, "")) cae(q, QLX_NOMEM);
     if (size != 0) {
       if (!stralloc_catb(&foo, num, fmt_ulong(num, size))) cae(q, QLX_NOMEM);
       if (!stralloc_append(&foo, "S")) cae(q, QLX_NOMEM);
     }
     if (count != 0) {
       if (size != 0)
	 if (!stralloc_append(&foo, ",")) cae(q, QLX_NOMEM);
       if (!stralloc_catb(&foo, num, fmt_ulong(num, count))) cae(q, QLX_NOMEM);
       if (!stralloc_append(&foo, "C")) cae(q, QLX_NOMEM);
     }
     if (!stralloc_0(&foo)) cae(q, QLX_NOMEM);
     logit(32, "%s: %s\n", ENV_QUOTA, foo.s);
     if (!env_put2(ENV_QUOTA, foo.s )) cae(q, QLX_NOMEM);
   } else {
     logit(32, "no quota set\n");
     if (!env_unset(ENV_QUOTA)) cae(q, QLX_NOMEM);
   }
   
   /*
    * get the forwarding addresses and build a list
    * equals to &jdoe@heaven.af.mil in .qmail
    */
   rv = qldap_get_attr(q, LDAP_FORWARDS, &foo, MULTI_VALUE);
   switch (rv) {
   case OK:
     logit(32, "%s: %s\n", ENV_FORWARDS, foo.s);
     if (!env_put2(ENV_FORWARDS, foo.s)) cae(q, QLX_NOMEM);
     break;
   case NOSUCH:
     if (!env_unset(ENV_FORWARDS)) cae(q, QLX_NOMEM);
     break;
   default:
     goto fail;
   }

   /*
    * get the path of the local delivery program
    * equals to |/usr/bin/program in .qmail
    */
   rv = qldap_get_attr(q, LDAP_PROGRAM, &foo, MULTI_VALUE);
   switch (rv) {
   case OK:
     logit(32, "%s: %s\n", ENV_PROGRAM, foo.s);
     if (check_progs(foo.s) == 0) cae(q, QLX_ILLVAL);
     if (!env_put2(ENV_PROGRAM, foo.s)) cae(q, QLX_NOMEM);
     break;
   case NOSUCH:
     if (!env_unset(ENV_PROGRAM)) cae(q, QLX_NOMEM);
     break;
   default:
     goto fail;
   }

   /*
    * prefetch the reply text so we can remove it if no deliverymode
    * is set.
    */
   rv = qldap_get_attr(q, LDAP_REPLYTEXT, &foo, SINGLE_VALUE);
   switch (rv) {
   case OK:
     logit(32, "%s: %s\n", ENV_REPLYTEXT, foo.s);
     if (!env_put2(ENV_REPLYTEXT, foo.s)) cae(q, QLX_NOMEM);
     break;
   case NOSUCH:
     if (!env_unset(ENV_REPLYTEXT)) cae(q, QLX_NOMEM);
     break;
   default:
     goto fail;
   }

   /*
    * get the deliverymode of the mailbox:
    * reply, noprogram, noforward, nolocal (nombox)
    */
   rv = qldap_get_attr(q, LDAP_MODE, &foo, MULTI_VALUE);
   switch (rv) {
   case OK:
     case_lowers(foo.s);
     logit(32, "%s: %s\n", ENV_MODE, foo.s);
     if (!env_put2(ENV_MODE, foo.s)) cae(q, QLX_NOMEM);
     break;
   case NOSUCH:
     if (!env_unset(ENV_MODE)) cae(q, QLX_NOMEM);
     if (!env_unset(ENV_REPLYTEXT)) cae(q, QLX_NOMEM);
     break;
   default:
     goto fail;
   }

   /* get the mode of the .qmail interpretion: ldaponly, dotonly, both, none */
   rv = qldap_get_dotmode(q, &foo);
   if (rv != OK) goto fail;
   logit(32, "%s: %s\n", ENV_DOTMODE, foo.s);
   if (!env_put2(ENV_DOTMODE, foo.s)) cae(q, QLX_NOMEM);

   /* ok, we finished, lets clean up and disconnect from the LDAP server */
   qldap_free(q);
   return 0;

fail:
   switch (rv) {
   case LDAP_BIND_UNREACH:
     cae(q, QLX_BINDTIMEOUT);
   case LDAP_BIND_AUTH:
     cae(q, QLX_LDAPAUTH);
   case NOSUCH:
   case NEEDED:
     cae(q, QLX_NEEDED);
   case BADVAL:
   case ILLVAL:
     cae(q, QLX_ILLVAL);
   case ERRNO:
     /* in most cases this error was a due to missing resources */
     cae(q, QLX_NOMEM);
   case TOOMANY:
     cae(q, QLX_TOOMANY);
   default:
     cae(q, QLX_LDAPFAIL);
   }
   /* NOTREACHED */
   return -1;
}
/* end -- LDAP server query routines */

stralloc lower = {0};
stralloc wildchars = {0};
struct cdb cdb;

void nughde_get(local)
char *local;
{
 char *(args[3]);
 int	pi[2],
	gpwpid,
	gpwstat,
	r,
	fd,
	flagwild;

 if (!stralloc_copys(&lower,"!")) _exit(QLX_NOMEM);
 if (!stralloc_cats(&lower,local)) _exit(QLX_NOMEM);
 if (!stralloc_0(&lower)) _exit(QLX_NOMEM);
 case_lowerb(lower.s,lower.len);

 if (!stralloc_copys(&nughde,"")) _exit(QLX_NOMEM);

 fd = open_read("users/cdb");
 if (fd == -1)
   if (errno != error_noent)
     _exit(QLX_CDB);

 if (fd != -1)
  {
   uint32 dlen;
   unsigned int i;

   cdb_init(&cdb, fd);
   r = cdb_seek(&cdb,"",0,&dlen);
   if (r != 1) _exit(QLX_CDB);
   if (!stralloc_ready(&wildchars,(unsigned int) dlen)) _exit(QLX_NOMEM);
   wildchars.len = dlen;
   if (cdb_bread(&cdb,wildchars.s,wildchars.len) == -1) _exit(QLX_CDB);

   i = lower.len;
   flagwild = 0;

   do
    {
     /* i > 0 */
     if (!flagwild || (i == 1) || (byte_chr(wildchars.s,wildchars.len,lower.s[i - 1]) < wildchars.len))
      {
       r = cdb_seek(&cdb,lower.s,i,&dlen);
       if (r == -1) _exit(QLX_CDB);
       if (r == 1)
        {
         if (!stralloc_ready(&nughde,(unsigned int) dlen)) _exit(QLX_NOMEM);
         nughde.len = dlen;
         if (cdb_bread(&cdb,nughde.s,nughde.len) == -1) _exit(QLX_CDB);
         if (flagwild)
	   if (!stralloc_cats(&nughde,local + i - 1)) _exit(QLX_NOMEM);
         if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
	 cdb_free(&cdb);
         close(fd);
         return;
        }
      }
     --i;
     flagwild = 1;
    }
   while (i);

   close(fd);
  }

 if (pipe(pi) == -1) _exit(QLX_SYS);
 args[0] = (char *)"bin/qmail-getpw";
 args[1] = local;
 args[2] = 0;
 switch(gpwpid = vfork())
  {
   case -1:
     _exit(QLX_SYS);
   case 0:
     if (prot_gid(auto_gidn) == -1) _exit(QLX_USAGE);
     if (prot_uid(auto_uidp) == -1) _exit(QLX_USAGE);
     close(pi[0]);
     if (fd_move(1,pi[1]) == -1) _exit(QLX_SYS);
     execv(*args,args);
     _exit(QLX_EXECPW);
  }
 close(pi[1]);

 if (slurpclose(pi[0],&nughde,128) == -1) _exit(QLX_SYS);

 if (wait_pid(&gpwstat,gpwpid) != -1)
  {
   if (wait_crashed(gpwstat)) _exit(QLX_SYS);
   if (wait_exitcode(gpwstat) != 0) _exit(wait_exitcode(gpwstat));
  }
}

stralloc ra = {0};

int spawn(fdmess,fdout,s,r,at)
int fdmess; int fdout;
char *s; char *r; unsigned int at;
{
 int f;

 if (!(f = fork()))
  {
   char *(args[11]);
   char *x;
   unsigned long u;
   unsigned int xlen;
   unsigned int n;
   unsigned int uid;
   unsigned int gid;
   int rv;
   
   log_init(fdout, -1, 1);

   sig_hangupdefault(); /* clear the hup sig handler for the child */

   /* copy the whole email address before the @ gets destroyed */
   if (!stralloc_copys(&ra,r)) _exit(QLX_NOMEM);
   if (!stralloc_0(&ra)) _exit(QLX_NOMEM);
   logit(16, "mailaddr: %S\n", &ra);

   r[at] = 0;
   if (!r[0]) _exit(0); /* <> */

   if (chdir(auto_qmail) == -1) _exit(QLX_USAGE);

   /* do the address lookup */
   rv = qldap_get(&ra, at, fdmess);
   switch (rv) {
   case 0:
     logit(16, "LDAP lookup succeeded\n");
     break;
   case 1:
     if (!stralloc_copys(&nughde,"")) _exit(QLX_NOMEM);
     if (localdelivery()) {
       /*
	* Do the local address lookup.
        * This is the standart qmail lookup funktion.
	*/
       logit(4, "LDAP lookup failed, using local db\n");
       nughde_get(r);
     } else {
       /* the alias-user handling for LDAP only mode */
       struct passwd *pw;
       char num[FMT_ULONG];

       logit(4, "LDAP lookup failed, using alias (no local db)\n");
       pw = getpwnam(auto_usera);
       if (!pw) _exit(QLX_NOALIAS);

       if (!stralloc_copys(&nughde, pw->pw_name)) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_uid))) 
	 _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_gid))) 
	 _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde, pw->pw_dir)) _exit(QLX_NOMEM); 
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde,"-")) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde,r)) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
     }
     break;
#ifdef QLDAP_CLUSTER
   case 2:
     /* hostname is different, so I reconnect */
     forward_mail(host.s, ra.s, s, fdmess, fdout);
     /* that's it. Function does not return */
#endif
#ifdef DUPEALIAS
   case 3:
     /* the alias-user handling for dupe handling */
     {
       struct passwd *pw;
       char num[FMT_ULONG];

       logit(4, "LDAP lookup got too many hits, using dupe alias\n");
       pw = getpwnam("dupealias");
       if (!pw) _exit(QLX_NOALIAS);

       if (!stralloc_copys(&nughde, pw->pw_name)) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_uid)))
	 _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_catb(&nughde,num,fmt_uint(num, pw->pw_gid)))
	 _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde, pw->pw_dir)) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde,"-")) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
       if (!stralloc_cats(&nughde,r)) _exit(QLX_NOMEM);
       if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
     }
     break;
#endif
   default:
     logit(2, "warning: ldap lookup freaky return value (%i)\n", rv);
     _exit(QLX_USAGE);
     break;
   } /* end switch */

   x = nughde.s;
   xlen = nughde.len;

   args[0] = (char *)"bin/qmail-local";
   args[1] = (char *)"--";
   args[2] = x;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   scan_ulong(x,&u);
   uid = u;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   scan_ulong(x,&u);
   gid = u;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   args[3] = x;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   args[4] = r;
   args[5] = x;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   args[6] = x;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   args[7] = r + at + 1;
   args[8] = s;
   args[9] = (char *)aliasempty;
   args[10] = 0;

   logit(8, "executing 'qmail-local -- %s %s %s %s %s %s %s %s' under uid=%u, gid=%u\n",
    args[2], args[3], args[4], args[5], args[6], args[7],
    args[8], args[9], uid, gid);

   if (fd_move(0,fdmess) == -1) _exit(QLX_SYS);
   if (fd_move(1,fdout) == -1) _exit(QLX_SYS);
   if (fd_copy(2,1) == -1) _exit(QLX_SYS);
   if (prot_gid(gid) == -1) _exit(QLX_USAGE);
   if (prot_uid(uid) == -1) _exit(QLX_USAGE);
   if (!getuid()) _exit(QLX_ROOT);

#ifdef AUTOHOMEDIRMAKE
   check_home(args[3], aliasempty);
#endif

   execv(*args,args);
   if (error_temp(errno)) _exit(QLX_EXECSOFT);
   _exit(QLX_EXECHARD);
  }
 return f;
}

#ifdef QLDAP_CLUSTER

void forward_mail(char *remote, char *to, char *from, int fdmess, int fdout)
{
  char *(args[5]);

  logit(8, "Forwarding to %s at host %s from %s ", to, remote, from);

  if (fd_move(0,fdmess) == -1) _exit(QLX_SYS);
  if (fd_move(1,fdout) == -1) _exit(QLX_SYS);
  if (fd_copy(2,1) == -1) _exit(QLX_SYS);
  if (prot_gid(auto_uida) == -1) _exit(QLX_USAGE);
  if (prot_uid(auto_gidn) == -1) _exit(QLX_USAGE);
  if (!getuid()) _exit(QLX_ROOT);

  args[0] = (char *)"bin/qmail-forward";
  args[1] = remote;
  args[2] = from;
  args[3] = to;
  args[4] = 0;

  execv(*args,args);
  if (error_temp(errno)) _exit(QLX_CLUSTERSOFT);
  _exit(QLX_CLUSTERHARD);
}

#endif

