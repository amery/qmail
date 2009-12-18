#include "fmt.h"
#include "qmail.h"
#include "now.h"
#include "datetime.h"
#include "date822fmt.h"
#include "received.h"

static int issafe(ch) char ch;
{
  if (ch == '.') return 1;
  if (ch == '@') return 1;
  if (ch == '%') return 1;
  if (ch == '+') return 1;
  if (ch == '/') return 1;
  if (ch == '=') return 1;
  if (ch == ':') return 1;
  if (ch == '-') return 1;
  if (ch == '_') return 1;
  if (ch == '#') return 1;
  if (ch == ']') return 1;
  if (ch == '[') return 1;
  if ((ch >= 'a') && (ch <= 'z')) return 1;
  if ((ch >= 'A') && (ch <= 'Z')) return 1;
  if ((ch >= '0') && (ch <= '9')) return 1;
  return 0;
}

void safeput(qqt,s)
struct qmail *qqt;
const char *s;
{
  char ch;
  while ((ch = *s++)) {
    if (!issafe(ch)) ch = '?';
    qmail_put(qqt,&ch,1);
  }
}

static char buf[DATE822FMT];

/* "Received: from relay1.uu.net (HELO uunet.uu.net) (7@192.48.96.5)\n" */
/* "  by silverton.berkeley.edu with SMTP; 26 Sep 1995 04:46:54 -0000\n" */

void 
received(qqt,protocol,local,remoteip,remotehost,remoteinfo,helo,mailfrom,rcptto)
struct qmail *qqt;
const char *protocol;
const char *local;
const char *remoteip;
const char *remotehost;
const char *remoteinfo;
const char *helo;
const char *mailfrom;
const char *rcptto;
{
  struct datetime dt;

  qmail_puts(qqt,"Received: from ");
  safeput(qqt,remotehost);
  if (helo) {
    qmail_puts(qqt," (HELO ");
    safeput(qqt,helo);
    qmail_puts(qqt,")");
  }
  qmail_puts(qqt," (");
  if (remoteinfo) {
    safeput(qqt,remoteinfo);
    qmail_puts(qqt,"@");
  }
  qmail_puts(qqt,"[");
  safeput(qqt,remoteip);
  qmail_puts(qqt,"])");

  if (mailfrom) {
    qmail_puts(qqt,"\n          (envelope-sender <");
    safeput(qqt,mailfrom);
    qmail_puts(qqt,">)");
  }
  qmail_puts(qqt,"\n          by ");

  safeput(qqt,local);
  qmail_puts(qqt," (qmail-ldap-1.03) with ");
  qmail_puts(qqt,protocol);

  if (rcptto) {
    qmail_puts(qqt,"\n          for <");
    safeput(qqt,rcptto);
    qmail_puts(qqt,">");
  }
  qmail_puts(qqt,"; ");
  
  datetime_tai(&dt,now());
  qmail_put(qqt,buf,date822fmt(buf,&dt));
}

