#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "substdio.h"
#include "subfd.h"
#include "exit.h"
#include "fmt.h"
#include "str.h"
#include "control.h"
#include "constmap.h"
#include "stralloc.h"
#include "direntry.h"
#include "auto_uids.h"
#include "auto_qmail.h"
#include "auto_break.h"
#include "auto_patrn.h"
#include "auto_spawn.h"
#include "auto_split.h"
#include "byte.h"

stralloc me = {0};
int meok;

stralloc ldapserver = {0};
int ldapok;

stralloc line = {0};
char num[FMT_ULONG];

void safeput(buf,len)
char *buf;
unsigned int len;
{
  char ch;

  while (len > 0) {
    ch = *buf;
    if ((ch < 32) || (ch > 126)) ch = '?';
    substdio_put(subfdout,&ch,1);
    ++buf;
    --len;
  }
}

void do_int(fn,def,pre,post)
char *fn;
char *def;
char *pre;
char *post;
{
  int i;
  substdio_puts(subfdout,"\n");
  substdio_puts(subfdout,fn);
  substdio_puts(subfdout,": ");
  switch(control_readint(&i,fn)) {
    case 0:
      substdio_puts(subfdout,"(Default.) ");
      substdio_puts(subfdout,pre);
      substdio_puts(subfdout,def);
      substdio_puts(subfdout,post);
      substdio_puts(subfdout,".\n");
      break;
    case 1:
      if (i < 0) i = 0;
      substdio_puts(subfdout,pre);
      substdio_put(subfdout,num,fmt_uint(num,i));
      substdio_puts(subfdout,post);
      substdio_puts(subfdout,".\n");
      break;
    default:
      substdio_puts(subfdout,"Oops! Trouble reading this file.\n");
      break;
  }
}

void do_ulong(fn,def,pre,post)
char *fn;
char *def;
char *pre;
char *post;
{
  unsigned long i;
  substdio_puts(subfdout,"\n");
  substdio_puts(subfdout,fn);
  substdio_puts(subfdout,": ");
  switch(control_readulong(&i,fn)) {
    case 0:
      substdio_puts(subfdout,"(Default.) ");
      substdio_puts(subfdout,pre);
      substdio_puts(subfdout,def);
      substdio_puts(subfdout,post);
      substdio_puts(subfdout,".\n");
      break;
    case 1:
      substdio_puts(subfdout,pre);
      substdio_put(subfdout,num,fmt_ulong(num,i));
      substdio_puts(subfdout,post);
      substdio_puts(subfdout,".\n");
      break;
    default:
      substdio_puts(subfdout,"Oops! Trouble reading this file.\n");
      break;
  }
}

void do_str(fn,flagme,def,pre)
char *fn;
int flagme;
char *def;
char *pre;
{
  substdio_puts(subfdout,"\n");
  substdio_puts(subfdout,fn);
  substdio_puts(subfdout,": ");
  switch(control_readline(&line,fn)) {
    case 0:
      substdio_puts(subfdout,"(Default.) ");
      if (!stralloc_copys(&line,def)) {
	substdio_puts(subfdout,"Oops! Out of memory.\n");
	break;
      }
      if (flagme && meok)
	if (!stralloc_copy(&line,&me)) {
	  substdio_puts(subfdout,"Oops! Out of memory.\n");
	  break;
	}
    case 1:
      substdio_puts(subfdout,pre);
      safeput(line.s,line.len);
      substdio_puts(subfdout,".\n");
      break;
    default:
      substdio_puts(subfdout,"Oops! Trouble reading this file.\n");
      break;
  }
}

int do_lst(fn,def,pre,post)
char *fn;
char *def;
char *pre;
char *post;
{
  unsigned int i;
  unsigned int j;

  substdio_puts(subfdout,"\n");
  substdio_puts(subfdout,fn);
  substdio_puts(subfdout,": ");
  switch(control_readfile(&line,fn, 0)) {
    case 0:
      substdio_puts(subfdout,"(Default.) ");
      substdio_puts(subfdout,def);
      substdio_puts(subfdout,"\n");
      return 0;
    case 1:
      substdio_puts(subfdout,"\n");
      i = 0;
      for (j = 0;j < line.len;++j)
	if (!line.s[j]) {
          substdio_puts(subfdout,pre);
          safeput(line.s + i,j - i);
          substdio_puts(subfdout,post);
          substdio_puts(subfdout,"\n");
	  i = j + 1;
	}
      return 1;
    default:
      substdio_puts(subfdout,"Oops! Trouble reading this file.\n");
      return -1;
  }
}

int main()
{
  DIR *dir;
  direntry *d;
  struct stat stmrh;
  struct stat stmrhcdb;

  substdio_puts(subfdout,"qmail home directory: ");
  substdio_puts(subfdout,auto_qmail);
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"user-ext delimiter: ");
  substdio_puts(subfdout,auto_break);
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"paternalism (in decimal): ");
  substdio_put(subfdout,num,fmt_uint(num, auto_patrn));
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"silent concurrency limit: ");
  substdio_put(subfdout,num,fmt_uint(num, auto_spawn));
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"subdirectory split: ");
  substdio_put(subfdout,num,fmt_uint(num, auto_split));
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"user ids: ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uida));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uidd));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uidl));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uido));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uidp));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uidq));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uidr));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_uids));
  substdio_puts(subfdout,".\n");

  substdio_puts(subfdout,"group ids: ");
  substdio_put(subfdout,num,fmt_uint(num, auto_gidn));
  substdio_puts(subfdout,", ");
  substdio_put(subfdout,num,fmt_uint(num, auto_gidq));
  substdio_puts(subfdout,".\n");

  if (chdir(auto_qmail) == -1) {
    substdio_puts(subfdout,"Oops! Unable to chdir to ");
    substdio_puts(subfdout,auto_qmail);
    substdio_puts(subfdout,".\n");
    substdio_flush(subfdout);
    _exit(111);
  }
  if (chdir("control") == -1) {
    substdio_puts(subfdout,"Oops! Unable to chdir to control.\n");
    substdio_flush(subfdout);
    _exit(111);
  }

  dir = opendir(".");
  if (!dir) {
    substdio_puts(subfdout,"Oops! Unable to open current directory.\n");
    substdio_flush(subfdout);
    _exit(111);
  }

  meok = control_readline(&me,"me");
  if (meok == -1) {
    substdio_puts(subfdout,"Oops! Trouble reading control/me.");
    substdio_flush(subfdout);
    _exit(111);
  }
  ldapok = control_readfile(&ldapserver,"ldapserver",0);
  byte_repl(ldapserver.s, ldapserver.len, '\0', ' ');
  if (ldapok == -1) {
    substdio_puts(subfdout,"Oops! Trouble reading control/ldapserver.");
    substdio_flush(subfdout);
    _exit(111);
  }
  substdio_puts(subfdout,"me: My name is ");
  substdio_put(subfdout, me.s, me.len);
  substdio_puts(subfdout,"\nldapserver: My ldap server is ");
  substdio_put(subfdout, ldapserver.s, ldapserver.len);
  substdio_puts(subfdout,"\n\n");


  do_lst("badmailfrom","Any MAIL FROM is allowed.",""," not accepted in MAIL FROM.");
  do_lst("badmailfrom-unknown","Any MAIL FROM from hosts without PTR is allowed.","",
	 " not accepted in MAIL FROM from host without PTR.");
  do_lst("badrcptto","Any RCPT TO is allowed.",""," not accepted in RCPT TO");
  if (stat("bigbrother",&stmrh) == 0)
    do_lst("bigbrother","No mail addresses are observed.","Observed mail address: ","");
  do_str("bouncefrom",0,"MAILER-DAEMON","Bounce user name is ");
  do_str("bouncehost",1,"bouncehost","Bounce host name is ");
  do_ulong("bouncemaxbytes","0","Bounce data limit is "," bytes");
  do_int("concurrencylocal","10","Local concurrency is ","");
  do_int("concurrencyremote","20","Remote concurrency is ","");
  do_lst("custombouncetext","No custombouncetext.","","");
  do_ulong("databytes","0","SMTP DATA limit is "," bytes");
  do_str("defaultdomain",1,"defaultdomain","Default domain name is ");
  do_str("defaulthost",1,"defaulthost","Default host name is ");
  do_str("dirmaker",0,"not defined","Program to create homedirs ");
  do_str("doublebouncehost",1,"doublebouncehost","2B recipient host: ");
  do_str("doublebounceto",0,"postmaster","2B recipient user: ");
  do_str("envnoathost",1,"envnoathost","Presumed domain name is ");
  do_lst("goodmailaddr","No good mail addresses.",""," is allowed in any case.");
  do_str("helohost",1,"helohost","SMTP client HELO host name is ");
  do_str("idhost",1,"idhost","Message-ID host name is ");
  do_str("localiphost",1,"localiphost","Local IP address becomes ");
  do_lst("locals","Messages for me are delivered locally.","Messages for "," are delivered locally.");
  do_str("me",0,"undefined! Uh-oh","My name is ");
  do_str("outgoingip",0,"0.0.0.0","Bind qmail-remote to ");
  do_ulong("pbscachesize","1048576","PBS cachesize is "," bytes");
  do_lst("pbsenv","No environment variables will be passed.","Environment Variable: ","");
  do_str("pbsip",0,"0.0.0.0","Bind PBS daemon to ");
  do_int("pbsport","2821","PBS deamon listens on port ","");
  do_str("pbssecret",0,"undefined! Uh-oh","PBS shared secret is ");
  do_lst("pbsservers","No PBS servers.","PBS server ",".");
  do_int("pbstimeout","600","PBS entries will be valid for "," seconds");  
  do_lst("percenthack","The percent hack is not allowed.","The percent hack is allowed for user%host@",".");
  do_str("plusdomain",1,"plusdomain","Plus domain name is ");
  do_str("qmqpcip",0,"0.0.0.0","Bind qmail-qmqpc to ");
  do_lst("qmqpservers","No QMQP servers.","QMQP server: ",".");
  do_int("queuelifetime","604800","Message lifetime in the queue is "," seconds");
  do_lst("quotawarning","No quotawarning.","","");
  do_lst("rbllist","No RBL listed.","RBL to check: ",".");

  if (do_lst("rcpthosts","SMTP clients may send messages to any recipient.","SMTP clients may send messages to recipients at ","."))
    do_lst("morercpthosts","No effect.","SMTP clients may send messages to recipients at ",".");
  else
    do_lst("morercpthosts","No rcpthosts; morercpthosts is irrelevant.","No rcpthosts; doesn't matter that morercpthosts has ",".");
  /* XXX: check morercpthosts.cdb contents */
  substdio_puts(subfdout,"\nmorercpthosts.cdb: ");
  if (stat("morercpthosts",&stmrh) == -1)
    if (stat("morercpthosts.cdb",&stmrhcdb) == -1)
      substdio_puts(subfdout,"(Default.) No effect.\n");
    else
      substdio_puts(subfdout,"Oops! morercpthosts.cdb exists but morercpthosts doesn't.\n");
  else
    if (stat("morercpthosts.cdb",&stmrhcdb) == -1)
      substdio_puts(subfdout,"Oops! morercpthosts exists but morercpthosts.cdb doesn't.\n");
    else
      if (stmrh.st_mtime > stmrhcdb.st_mtime)
        substdio_puts(subfdout,"Oops! morercpthosts.cdb is older than morercpthosts.\n");
      else
        substdio_puts(subfdout,"Modified recently enough; hopefully up to date.\n");

  do_lst("relaymailfrom","Relaymailfrom not enabled.","Envelope senders allowed to relay: ",".");
  do_str("smtpgreeting",1,"smtpgreeting","SMTP greeting: 220 ");
  do_lst("smtproutes","No artificial SMTP routes.","SMTP route: ","");
  do_int("timeoutconnect","60","SMTP client connection timeout is "," seconds");
  do_int("timeoutremote","1200","SMTP client data timeout is "," seconds");
  do_int("timeoutsmtpd","1200","SMTP server data timeout is "," seconds");
  do_lst("virtualdomains","No virtual domains.","Virtual domain: ","");


  substdio_puts(subfdout,"\n\n\nNow the qmail-ldap specific files:\n");
  do_str("ldapbasedn",0,"NULL","LDAP basedn: ");
  do_lst("ldapserver","undefined! Uh-oh","","");
  do_str("ldaplogin",0,"NULL","LDAP login: ");
  do_str("ldappassword",0,"NULL","LDAP password: ");
  do_int("ldaptimeout","30","LDAP server timeout is "," seconds");
  do_str("ldapuid",0,"not defined","Default UID is ");
  do_str("ldapgid",0,"not defined","Default GID is ");
  do_str("ldapobjectclass",0,"not defined","The objectclass to limit ldap filter is ");
  do_str("ldapmessagestore",0,"not defined","Prefix for non absolute paths is ");
  do_str("ldapdefaultdotmode",0,"ldaponly","Default dot mode for ldap users is ");
  do_ulong("defaultquotasize","0","Mailbox size quota is "," bytes (0 is unlimited)");
  do_ulong("defaultquotacount","0","Mailbox count quota is "," messages (0 is unlimited)");
  do_int("ldaplocaldelivery","1","Local passwd lookup is "," (1 = on, 0 = off)");
  do_int("ldaprebind","0","Ldap rebinding is "," (1 = on, 0 = off)");
  do_int("ldapcluster","0","Clustering is "," (1 = on, 0 = off)");
  do_lst("ldapclusterhosts","Messages for me are not redirected.",
	 "Messages for "," are not redirected.");

  substdio_puts(subfdout,"\n");
  
  
  while ((d = readdir(dir))) {
    if (str_equal(d->d_name,".")) continue;
    if (str_equal(d->d_name,"..")) continue;
    if (str_equal(d->d_name,"badmailfrom")) continue;
    if (str_equal(d->d_name,"badmailfrom-unknown")) continue;
    if (str_equal(d->d_name,"badrcptto")) continue;
    if (str_equal(d->d_name,"bigbrother")) continue;
    if (str_equal(d->d_name,"bouncefrom")) continue;
    if (str_equal(d->d_name,"bouncehost")) continue;
    if (str_equal(d->d_name,"bouncemaxbytes")) continue;
    if (str_equal(d->d_name,"concurrencylocal")) continue;
    if (str_equal(d->d_name,"concurrencyremote")) continue;
    if (str_equal(d->d_name,"custombouncetext")) continue;
    if (str_equal(d->d_name,"databytes")) continue;
    if (str_equal(d->d_name,"defaultdomain")) continue;
    if (str_equal(d->d_name,"defaulthost")) continue;
    if (str_equal(d->d_name,"defaultquotacount")) continue;
    if (str_equal(d->d_name,"defaultquotasize")) continue;
    if (str_equal(d->d_name,"dirmaker")) continue;
    if (str_equal(d->d_name,"doublebouncehost")) continue;
    if (str_equal(d->d_name,"doublebounceto")) continue;
    if (str_equal(d->d_name,"envnoathost")) continue;
    if (str_equal(d->d_name,"helohost")) continue;
    if (str_equal(d->d_name,"goodmailaddr")) continue;
    if (str_equal(d->d_name,"idhost")) continue;
    if (str_equal(d->d_name,"ldapbasedn")) continue;
    if (str_equal(d->d_name,"ldapcluster")) continue;
    if (str_equal(d->d_name,"ldapclusterhosts")) continue;
    if (str_equal(d->d_name,"ldapdefaultdotmode")) continue;
    if (str_equal(d->d_name,"ldapgid")) continue;
    if (str_equal(d->d_name,"ldaplocaldelivery")) continue;
    if (str_equal(d->d_name,"ldaplogin")) continue;
    if (str_equal(d->d_name,"ldapmessagestore")) continue;
    if (str_equal(d->d_name,"ldapobjectclass")) continue;
    if (str_equal(d->d_name,"ldappassword")) continue;
    if (str_equal(d->d_name,"ldaprebind")) continue;
    if (str_equal(d->d_name,"ldapserver")) continue;
    if (str_equal(d->d_name,"ldaptimeout")) continue;
    if (str_equal(d->d_name,"ldapuid")) continue;
    if (str_equal(d->d_name,"localiphost")) continue;
    if (str_equal(d->d_name,"locals")) continue;
    if (str_equal(d->d_name,"me")) continue;
    if (str_equal(d->d_name,"morercpthosts")) continue;
    if (str_equal(d->d_name,"morercpthosts.cdb")) continue;
    if (str_equal(d->d_name,"outgoingip")) continue;
    if (str_equal(d->d_name,"pbscachesize")) continue;
    if (str_equal(d->d_name,"pbsenv")) continue;
    if (str_equal(d->d_name,"pbsip")) continue;
    if (str_equal(d->d_name,"pbsport")) continue;
    if (str_equal(d->d_name,"pbssecret")) continue;
    if (str_equal(d->d_name,"pbsservers")) continue;
    if (str_equal(d->d_name,"pbstimeout")) continue;
    if (str_equal(d->d_name,"percenthack")) continue;
    if (str_equal(d->d_name,"plusdomain")) continue;
    if (str_equal(d->d_name,"qmqpcip")) continue;
    if (str_equal(d->d_name,"qmqpservers")) continue;
    if (str_equal(d->d_name,"queuelifetime")) continue;
    if (str_equal(d->d_name,"quotawarning")) continue;
    if (str_equal(d->d_name,"rbllist")) continue;
    if (str_equal(d->d_name,"rcpthosts")) continue;
    if (str_equal(d->d_name,"relaymailfrom")) continue;
    if (str_equal(d->d_name,"smtpgreeting")) continue;
    if (str_equal(d->d_name,"smtproutes")) continue;
    if (str_equal(d->d_name,"timeoutconnect")) continue;
    if (str_equal(d->d_name,"timeoutremote")) continue;
    if (str_equal(d->d_name,"timeoutsmtpd")) continue;
    if (str_equal(d->d_name,"virtualdomains")) continue;
    if (str_equal(d->d_name,"ldapusername") ||
	str_equal(d->d_name,"ldappasswdappend") ||
	str_equal(d->d_name,"ldapdefaultquota") ||
	str_equal(d->d_name,"rblonlyheader") ||
	str_equal(d->d_name,"maxrcptcount") ||
	str_equal(d->d_name,"tarpitdelay") ||
	str_equal(d->d_name,"tarpitcount")) {
        substdio_puts(subfdout,d->d_name);
        substdio_puts(subfdout,": No longer used, please remove.\n");
        continue;
    }
    substdio_puts(subfdout,d->d_name);
    substdio_puts(subfdout,": I have no idea what this file does.\n");
  }

  substdio_flush(subfdout);
  return 0;
}
