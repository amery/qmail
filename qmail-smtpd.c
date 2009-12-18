#include <unistd.h>
#include "sig.h"
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "auto_break.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "rcpthosts.h"
#include "rbl.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "dns.h"
#include "smtpcall.h"
#include "qmail-ldap.h"
#include "limit.h"
#ifdef SMTPEXECCHECK
#include "execcheck.h"
#endif
#ifdef TLS_SMTPD
#include <openssl/ssl.h>
SSL *ssl = NULL;
#endif
#ifdef DATA_COMPRESS
/* zlib needs to be after openssl includes or build will fail */
#include <zlib.h>
#endif

#define MAXHOPS 100
#define MAXLINELEN 10000
unsigned long databytes = 0;
int timeout = 1200;

#ifdef TLS_SMTPD
int flagtimedout = 0;
void sigalrm()
{
 flagtimedout = 1;
}
int ssl_timeoutread(int tout, int fd, void *buf, int n)
{
 int r; int saveerrno;
 if (flagtimedout) { errno = error_timeout; return -1; }
 alarm(tout);
 r = SSL_read(ssl,buf,n);
 saveerrno = errno;
 alarm(0);
 if (flagtimedout) { errno = error_timeout; return -1; }
 errno = saveerrno;
 return r;
}
int ssl_timeoutwrite(int tout, int fd, const void *buf, int n)
{
 int r; int saveerrno;
 if (flagtimedout) { errno = error_timeout; return -1; }
 alarm(tout);
 r = SSL_write(ssl,buf,n);
 saveerrno = errno;
 alarm(0);
 if (flagtimedout) { errno = error_timeout; return -1; }
 errno = saveerrno;
 return r;
}
#endif

void die_write(void);

int safewrite(int fd, void *buf, int len)
{
  int r;
#ifdef TLS_SMTPD
  if (ssl)
    r = ssl_timeoutwrite(timeout,fd,buf,len);
  else
#endif
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) die_write();
  return r;
}

char ssoutbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

void flush(void) { substdio_flush(&ssout); }
void out(const char *s) { substdio_puts(&ssout,s); }

/* level 0 = no logging
         1 = fatal errors
         2 = connection setup and warnings
         3 = verbose */

int loglevel = 0;

void logpid(int level)
{
  char pidstring[FMT_ULONG];
  if (level > loglevel) return;
  substdio_puts(subfderr,"qmail-smtpd ");
  pidstring[fmt_uint(pidstring, getpid())] = 0;
  substdio_puts(subfderr,pidstring);
  substdio_puts(subfderr,": ");
}

void logline(int level, const char *string)
{
  if (level > loglevel) return;
  logpid(level);
  substdio_puts(subfderr,string);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void logline2(int level, const char *s1, const char *s2)
{
  if (level > loglevel) return;
  logpid(level);
  substdio_puts(subfderr,s1);
  substdio_puts(subfderr,s2);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void logstring(int level, const char *string)
{
  if (level > loglevel) return;
  substdio_puts(subfderr,string);
}

void logflush(int level)
{
  if (level > loglevel) return;
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void cleanup(void);

const char *remoteip;

void die_read(void) { logline(1,"read error or connection closed"); cleanup(); _exit(1); }
void die_write(void) { logline(1,"write error, connection closed"); cleanup(); _exit(1); }
void die_alarm(void) { out("451 timeout (#4.4.2)\r\n"); logline(1,"connection timed out, closing connection"); flush(); cleanup(); _exit(1); }
void die_nomem(void) { out("421 out of memory (#4.3.0)\r\n"); logline(1,"out of memory, closing connection"); flush(); cleanup(); _exit(1); }
void die_control(void) { out("421 unable to read controls (#4.3.0)\r\n"); logline(1,"unable to read controls, closing connection"); flush(); _exit(1); }
void die_ipme(void) { out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); logline(1,"unable to figure out my IP address, closing connection"); flush(); _exit(1); }
void straynewline(void) { out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); logline(1,"stray new line detected, closing connection"); flush(); _exit(1); }
void oversizedline(void) { out("500 Text line too long."); logline(1,"Oversized line in data part, closing connection"); flush(); _exit(1); }
void err_qqt(void) { out("451 qqt failure (#4.3.0)\r\n"); }
void err_dns(void) { out("421 DNS temporary failure at return MX check, try again later (#4.3.0)\r\n"); }
void err_soft(char *s) { out("451 "); out(s); out("\r\n"); logline2(1,"temporary verify error: ", s); }
void err_bmf(void) { out("553 sorry, your mail was administratively denied. (#5.7.1)\r\n"); }
void err_bmfunknown(void) { out("553 sorry, your mail from a host ["); out(remoteip); out("] without valid reverse DNS was administratively denied (#5.7.1)\r\n"); }
void err_maxrcpt(void) { out("553 sorry, too many recipients (#5.7.1)\r\n"); }
void err_nogateway(void) { out("553 sorry, relaying denied from your location ["); out(remoteip); out("] (#5.7.1)\r\n"); }
void err_badbounce(void) { out("550 sorry, I don't accept bounce messages with more than one recipient. Go read RFC2821. (#5.7.1)\r\n"); }
void err_unimpl(const char *arg) { out("502 unimplemented (#5.5.1)\r\n"); logline2(3,"unrecognized command: ",arg); }
void err_size(void) { out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n"); logline(3,"message denied because: 'SMTP SIZE' too big"); }
void err_syntax(void) { out("555 syntax error (#5.5.4)\r\n"); }
void err_relay(void) { out("553 sorry, we don't relay for ["); out(remoteip); out("] (#5.7.1)\r\n"); }
void err_wantmail(void) { out("503 MAIL first (#5.5.1)\r\n"); logline(4,"'mail from' first"); }
void err_wantrcpt(void) { out("503 RCPT first (#5.5.1)\r\n"); logline(4,"'rcpt to' first"); }

void err_noop(char *arg) { out("250 ok\r\n"); logline(4,"'noop'"); }
void err_vrfy(char *arg) { out("252 send some mail, i'll try my best\r\n"); logline2(4,"vrfy for: ",arg); }

void err_rbl(char *arg) { out("553 sorry, your mailserver ["); out(remoteip); out("] is rejected by "); out(arg); out("\r\n"); }
void err_deny(void) { out("553 sorry, mail from your location ["); out(remoteip); out("] is administratively denied (#5.7.1)\r\n"); }
void err_badrcptto(void) { out("553 sorry, mail to that recipient is not accepted (#5.7.1)\r\n"); }
void err_554msg(const char *arg)
{
	out("554 "); out(arg); out("\r\n");
	logline2(3,"message denied: ",arg);
}


stralloc me = {0};
stralloc greeting = {0};
stralloc cookie = {0};

void smtp_greet(const char *code)
{
  substdio_puts(&ssout,code);
  substdio_puts(&ssout,me.s);
  substdio_puts(&ssout," ESMTP ");
  substdio_put(&ssout,greeting.s,greeting.len);
  if (cookie.len > 0) {
    substdio_puts(&ssout," ");
    substdio_put(&ssout,cookie.s,cookie.len);
  }
  out("\r\n");
}
void smtp_line(const char *code)
{
  substdio_puts(&ssout,code);
  substdio_puts(&ssout,me.s);
  substdio_puts(&ssout," ");
  substdio_put(&ssout,greeting.s,greeting.len);
  out("\r\n");
}
void smtp_help(char *arg)
{
  out("214-qmail home page: http://pobox.com/~djb/qmail.html\r\n");
  out("214 qmail-ldap patch home page: http://www.nrg4u.com\r\n");
  logline(4,"help requested");
}
void smtp_quit(char *arg)
{
  if (!stralloc_copys(&greeting,"Goodbye."))
    die_nomem();
  smtp_line("221 ");
  logline(4,"quit, closing connection");
  flush();
  cleanup();
  _exit(0);
}
void err_quit(void)
{
  logline(4,"force closing connection");
  flush();
  cleanup();
  _exit(0);
}

const char *remotehost;
const char *remoteinfo;
const char *local;
const char *relayclient;
const char *relayok;
const char *greeting550;
const char *greeting421;
int  spamflag = 0;

stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */

void dohelo(const char *arg)
{
  if (!stralloc_copys(&helohost,arg)) die_nomem(); 
  if (!stralloc_0(&helohost)) die_nomem(); 
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
}

int liphostok = 0;
stralloc liphost = {0};
int bmfok = 0;
stralloc bmf = {0};
struct constmap mapbmf;
int bmfunknownok = 0;
stralloc bmfunknown = {0};
struct constmap mapbmfunknown;
int rmfok = 0;
stralloc rmf = {0};
struct constmap maprmf;
int brtok = 0;
stralloc brt = {0};
struct constmap mapbadrcptto;
int gmaok = 0;
stralloc gma = {0};
struct constmap mapgma;
int rblok = 0;
int rbloh = 0;
int errdisconnect = 0;
int nobounce = 0;
int sanitycheck = 0;
int returnmxcheck = 0;
int blockrelayprobe = 0;
unsigned int tarpitcount = 0;
unsigned int tarpitdelay = 5;
unsigned int maxrcptcount = 0;
int sendercheck = 0;
int rcptcheck = 0;
int ldapsoftok = 0;
int flagauth = 0;
int needauth = 0;
int needssl = 0;
int flagauthok = 0;
const char *authprepend;
#ifdef TLS_SMTPD
stralloc sslcert = {0};
#endif
char smtpsize[FMT_ULONG];

void setup(void)
{
#ifdef TLS_SMTPD
  char *sslpath;
#endif
  char *x, *l;
  unsigned long u;

  l = env_get("LOGLEVEL");
  if (l) { scan_ulong(l,&u); loglevel = u > 4 ? 4 : u; }

  if (control_init() == -1) die_control();

  if (control_readline(&me,"control/me") != 1)
    die_control();
  if (!stralloc_0(&me)) die_nomem();

  if (control_rldef(&greeting,"control/smtpgreeting", 0, "") == -1)
    die_control();

  if (control_rldef(&cookie,"control/smtpclustercookie", 0, "") == -1)
    die_control();
  if (cookie.len > 32) cookie.len = 32;

  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();

  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;

#ifdef TLS_SMTPD
  sslpath = env_get("SSLCERT");
  if (!sslpath) {
    sslpath = (char *)"control/smtpcert";
    if (control_readline(&sslcert, sslpath) == -1)
      die_control();
  } else
    if (!stralloc_copys(&sslcert, sslpath)) die_nomem();
  if (!stralloc_0(&sslcert)) die_nomem();
#endif

  x = env_get("TARPITCOUNT");
  if (x) { scan_ulong(x,&u); tarpitcount = u >= UINT_MAX ? UINT_MAX - 1 : u; }

  x = env_get("TARPITDELAY");
  if (x) { scan_ulong(x,&u); tarpitdelay = u > INT_MAX ? INT_MAX : u; }

  x = env_get("MAXRCPTCOUNT");
  if (x) { scan_ulong(x,&u); maxrcptcount = u >= UINT_MAX ? UINT_MAX - 1 : u; };

  if (rcpthosts_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  bmfunknownok = control_readfile(&bmfunknown,"control/badmailfrom-unknown",0);
  if (bmfunknownok == -1) die_control();
  if (bmfunknownok)
    if (!constmap_init(&mapbmfunknown,bmfunknown.s,bmfunknown.len,0))
      die_nomem();

  rmfok = control_readfile(&rmf,"control/relaymailfrom",0);
  if (rmfok == -1) die_control();
  if (rmfok)
    if (!constmap_init(&maprmf,rmf.s,rmf.len,0)) die_nomem();

  brtok = control_readfile(&brt,"control/badrcptto",0);
  if (brtok == -1) die_control();
  if (brtok)
    if (!constmap_init(&mapbadrcptto,brt.s,brt.len,0)) die_nomem();

  gmaok = control_readfile(&gma,"control/goodmailaddr",0);
  if (gmaok == -1) die_control();
  if (gmaok)
    if (!constmap_init(&mapgma,gma.s,gma.len,0)) die_nomem();

  if (env_get("RBL")) {
    rblok = rblinit();
    if (rblok == -1) die_control();
    if (env_get("RBLONLYHEADER")) rbloh = 1;
  }

  if (env_get("SMTP550DISCONNECT")) errdisconnect = 1;
  if (env_get("NOBOUNCE")) nobounce = 1;
  if (env_get("SANITYCHECK")) sanitycheck = 1;
  if (env_get("RETURNMXCHECK")) returnmxcheck = 1;
  if (env_get("BLOCKRELAYPROBE")) blockrelayprobe = 1;
  if (env_get("SENDERCHECK")) {
    sendercheck = 1;
    if (!case_diffs("LOOSE",env_get("SENDERCHECK"))) sendercheck = 2;
    if (!case_diffs("STRICT",env_get("SENDERCHECK"))) sendercheck = 3;
  }
  if (env_get("RCPTCHECK")) rcptcheck = 1;
  if (env_get("LDAPSOFTOK")) ldapsoftok = 1;
  greeting550 = env_get("550GREETING");
  greeting421 = env_get("421GREETING");
  relayok = relayclient = env_get("RELAYCLIENT");

  if (env_get("SMTPAUTH")) {
    flagauth = 1;
    if (!case_diffs("TLSREQUIRED", env_get("SMTPAUTH"))) needssl = 1;
  }
  if (env_get("AUTHREQUIRED")) needauth = 1;
  authprepend = env_get("AUTHPREPEND");

#ifdef SMTPEXECCHECK
  execcheck_setup();
#endif

  if (control_readulong(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) scan_ulong(x,&databytes);
  if (!(databytes + 1)) --databytes; /* poor man overflow detection */
 
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");

  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";

  logpid(2);
  logstring(2,"connection from "); logstring(2,remoteip);
  logstring(2," ("); logstring(2,remotehost);
  if (remoteinfo) { logstring(2,", "); logstring(2,remoteinfo); }
  logstring(2,") to "); logstring(2,local);
  logflush(2);

  logpid(3);
  logstring(3, "enabled options: ");
  if (databytes != 0) {
    smtpsize[fmt_ulong(smtpsize, databytes)] = 0;
    logstring(3,"max msg size: ");
    logstring(3,smtpsize);
    logstring(3," ");
  }
  if (greeting550) logstring(3,"greeting550 ");
#ifdef TLS_SMTPD
  if (sslcert.s && *sslcert.s) logstring(3, "starttls ");
#endif
  if (relayclient) logstring(3,"relayclient ");
  if (sanitycheck) logstring(3,"sanitycheck ");
  if (returnmxcheck) logstring(3,"returnmxcheck ");
  if (blockrelayprobe) logstring(3,"blockrelayprobe ");
  if (nobounce) logstring(3,"nobounce ");
  if (rblok) logstring(3,"rblcheck ");
  if (rbloh) logstring(3,"rblonlyheader ");
  if (sendercheck) logstring(3,"sendercheck");
  if (sendercheck == 1) logstring(3," ");
  if (sendercheck == 2) logstring(3,"-loose ");
  if (sendercheck == 3) logstring(3,"-strict ");
  if (rcptcheck) logstring(3,"rcptcheck ");
  if (ldapsoftok) logstring(3,"ldapsoftok ");
  if (flagauth) logstring(3, "smtp-auth");
  if (needssl) logstring(3, "-tls-required ");
  else logstring(3, " ");
  if (needauth) logstring(3, "authrequired ");
#ifdef SMTPEXECCHECK
  if (execcheck_on()) logstring(3, "rejectexecutables ");
#endif
  if (errdisconnect) logstring(3,"smtp550disconnect ");
#ifdef ALTQUEUE
  if (env_get("QMAILQUEUE")) {
    logstring(3,"qmailqueue ");
    logstring(3,env_get("QMAILQUEUE"));
  }
#endif
  logflush(3);

  dohelo(remotehost);
}


stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */

int addrparse(char *arg)
{
  unsigned int i;
  char ch;
  char terminator;
  struct ip_address ip;
  int flagesc;
  int flagquoted;
 
  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    if (*arg == '\0') return 0;
    while (*arg == ' ') ++arg;
  }

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0;(ch = arg[i]);++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[')
        if (!addr.s[i + 1 + ip_scanbracket(addr.s + i + 1,&ip)])
          if (ipme_is(&ip)) {
            addr.len = i + 1;
            if (!stralloc_cat(&addr,&liphost)) die_nomem();
            if (!stralloc_0(&addr)) die_nomem();
          }
  }

  if (addr.len > 900) return 0;
  return 1;
}

stralloc checkhost = {0};
ipalloc checkip = {0};

int badmxcheck(char *dom)
{
  int ret = 0;
  unsigned long r;

  if (!*dom) return (DNS_HARD);
  if (!stralloc_copys(&checkhost,dom)) return (DNS_SOFT);

  r = now() + (getpid() << 16);
  switch (dns_mxip(&checkip,&checkhost,r))
  {
    case DNS_MEM:
    case DNS_SOFT:
         ret = DNS_SOFT;
         break;
    case DNS_HARD:
         ret = DNS_HARD;
         break;
    case 1:
         if (checkip.len <= 0) ret = DNS_SOFT;
         break;
    default:
         if (checkip.len <= 0) ret = DNS_HARD;
         break;
  }
  return (ret);
}

stralloc parameter = {0};

char *getparameter(char *arg, const char *name)
{
  unsigned int i;
  char ch;
  char terminator;
  int flagesc;
  int flagquoted;

  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    while (*arg == ' ') ++arg;
  }

  flagesc = 0;
  flagquoted = 0;
  for (i = 0;(ch = arg[i]);++i) { /* skipping addr, respecting quotes */
    if (flagesc) {
      flagesc = 0;
    } else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: break;
      }
    }
  }
  if (!arg[i++]) return (char *)0; /* no parameters */
  arg += i;
  do {
    while (*arg == ' ') if (!*arg++) return (char *)0;
    if (case_diffb(arg, str_len(name), name) == 0) {
      arg += str_len(name);
      if (*arg++ == '=') {
	i = str_chr(arg, ' ');
	if (!stralloc_copyb(&parameter, arg, i)) die_nomem();
	if (!stralloc_0(&parameter)) die_nomem();
	return parameter.s;
      }
    }
    while (*arg != ' ') if (!*arg++) return (char *)0;
  } while (1);
}

int sizelimit(char *arg)
{
  char *size;
  unsigned long sizebytes = 0;

  size = getparameter(arg, "SIZE");
  if (!size) return 1;

  scan_ulong(size, &sizebytes);
  return databytes >= sizebytes;
}


int bmfcheck(void)
{
  unsigned int j;

  if (!bmfok) return 0;
  if (constmap(&mapbmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
  {
    if (constmap(&mapbmf,addr.s + j,addr.len - j - 1)) return 1;
    if (constmap(&mapbmf,addr.s, j + 1)) return 1;
  }
  return 0;
}

int bmfunknowncheck(void)
{
  unsigned int j;

  if (!bmfunknownok) return 0;
  if (case_diffs(remotehost,"unknown")) return 0;
  if (constmap(&mapbmfunknown,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbmfunknown,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}

int seenmail = 0;
stralloc mailfrom = {0};
stralloc rcptto = {0};
unsigned int rcptcount;

int rmfcheck(void)
{
  unsigned int j;

  if (!rmfok) return 0;
  if (constmap(&maprmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&maprmf,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}

int addrallowed(void)
{
  int r;

  r = rcpthosts(addr.s,addr.len - 1);
  if (r == -1) die_control();
  return r;
}

int addrlocals(void)
{
  int r;

  r = localhosts(addr.s, addr.len - 1);
  if (r == -1) die_control();
  return r;
}

int rcptdenied(void)
{
  unsigned int j;

  if (!brtok) return 0;
  if (constmap(&mapbadrcptto, addr.s, addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbadrcptto, addr.s + j, addr.len - j - 1))
      return 1;
  return 0;
}

stralloc gmaddr;

int goodmailaddr(void)
{
  unsigned int at;
#ifdef DASH_EXT
  unsigned int ext;
  int extcnt;
#endif

  if (!gmaok) return 0;
  if (constmap(&mapgma, addr.s, addr.len - 1)) return 1;
  at = byte_rchr(addr.s,addr.len,'@');
  if (at < addr.len) {
    if (constmap(&mapgma, addr.s + at, addr.len - at - 1))
      return 1;
    if (constmap(&mapgma, addr.s, at + 1))
      return 1;
#ifdef DASH_EXT
    /* foo-catchall@domain.org */
    for (ext = 0, extcnt = 1; ext < at && extcnt <= DASH_EXT_LEVELS; ext++)
      if (addr.s[ext] == *auto_break)
	extcnt++;
    for (;;) {
      if (addr.s[ext] == *auto_break) {
	if (!stralloc_copyb(&gmaddr, addr.s, ext + 1))
	  die_nomem();
	if (!stralloc_cats(&gmaddr, LDAP_CATCH_ALL))
	  die_nomem();
	if (!stralloc_catb(&gmaddr, addr.s + at, addr.len - at - 1))
	  die_nomem();
	if (constmap(&mapgma, gmaddr.s, gmaddr.len))
	  return 1;
      }
      if (ext == 0)
	break;
      ext--;
    }
#endif
    /* catchall@domain.org */
    if (!stralloc_copys(&gmaddr, LDAP_CATCH_ALL))
      die_nomem();
    if (!stralloc_catb(&gmaddr, addr.s + at, addr.len - at - 1))
      die_nomem();
    if (constmap(&mapgma, gmaddr.s, gmaddr.len))
      return 1;
  }
  return 0;
}

struct call ccverify;
stralloc verifyresponse;
int flagverify = 0;

void ldaplookupdone(void)
{
  if (flagverify != 1) return;
  call_close(&ccverify);
  flagverify = 0;
  return;
}

int ldaplookup(char *address, char **s)
{
  char ch;
  
  if (flagverify == -1) return -1;
  if (flagverify == 0) {
    if (call_open(&ccverify, "bin/qmail-verify", 30, 0) == -1) {
      flagverify = -1;
      return -1;
    }
    flagverify = 1;
  }
  call_puts(&ccverify, address); call_putflush(&ccverify, "", 1);
  if (call_getc(&ccverify, &ch) != 1)
    goto fail;
  switch (ch) {
  case 'K':
    return 1;
  case 'D':
    /* get response */
    if (!stralloc_copys(&verifyresponse, "")) die_nomem();
    while (call_getc(&ccverify, &ch) == 1) {
      if (!stralloc_append(&verifyresponse, &ch)) die_nomem();
      if (ch == 0) {
	*s = verifyresponse.s;
	return 0;
      }
    }
    break;
  case 'Z':
    /* soft error */
    if (!stralloc_copys(&verifyresponse, "")) die_nomem();
    while (call_getc(&ccverify, &ch) == 1) {
      if (!stralloc_append(&verifyresponse, &ch)) die_nomem();
      if (ch == 0) {
	*s = verifyresponse.s;
	return -1;
      }
    }
    break;
  default:
    break;
  }
fail:
  flagverify = -1;
  call_close(&ccverify);
  return -1;
}

int relayprobe(void) /* relay probes trying stupid old sendwhale bugs */
{
  unsigned int j;
  for (j = byte_rchr(addr.s, addr.len, '@'); j-- > 0; ) {
    if (addr.s[j] == '@') return 1; /* double @ */
    if (addr.s[j] == '%') return 1; /* percent relaying */
    if (addr.s[j] == '!') return 1; /* UUCP bang path */
  }
  return 0;
}


void smtp_helo(char *arg)
{
  smtp_line("250 ");
  seenmail = 0; dohelo(arg);
  logline2(4, "remote helo: ", arg);
}

void smtp_ehlo(char *arg)
{
  smtp_line("250-");
  out("250-PIPELINING\r\n");
  if (databytes != 0) {
    smtpsize[fmt_ulong(smtpsize, databytes)] = 0;
    out("250-SIZE "); out(smtpsize); out("\r\n");
  }
#ifdef DATA_COMPRESS
  out("250-DATAZ\r\n");
#endif
#ifdef TLS_SMTPD
  if (!ssl && sslcert.s && *sslcert.s)
    out("250-STARTTLS\r\n");
#endif
#ifdef TLS_SMTPD
  if (!needssl || ssl)
#endif
  if (flagauth)
    out("250-AUTH LOGIN PLAIN\r\n");
  out("250 8BITMIME\r\n");

  seenmail = 0; dohelo(arg);
  logline2(4,"remote ehlo: ",arg);
}

void smtp_rset(char *arg)
{
  seenmail = 0;
  if (relayclient != NULL && relayok == NULL)
	  env_unset("RELAYCLIENT");
  relayclient = relayok; /* restore original relayclient setting */
  out("250 flushed\r\n");
  logline(4,"remote rset");
}

struct qmail qqt;

void smtp_mail(char *arg)
{
  unsigned int i,j;
  char *rblname;
  int bounceflag = 0;

  /* address syntax check */
  if (!addrparse(arg))
  {
    err_syntax(); 
    logline2(3,"RFC2821 syntax error in mail from: ",arg);
    if (errdisconnect) err_quit();
    return;
  }

  logline2(4,"mail from: ",addr.s);

  if (needauth && !flagauthok) {
    out("530 authentication needed\r\n");
    logline(3, "auth needed");
    if (errdisconnect) err_quit();
    return;
  }

  /* check if we are authenticated, if yes enable relaying */
  if (flagauthok && relayclient == 0) {
    relayclient = "";
    if (!env_put("RELAYCLIENT=")) die_nomem();
  }

  /* smtp size check */
  if (databytes && !sizelimit(arg))
  {
    err_size(); /* logging is done in error routine */
    if (errdisconnect) err_quit();
    return;
  }

  /* bad mailfrom check */
  if (bmfcheck())
  {
    err_bmf();
    logline2(3,"bad mailfrom: ",addr.s);
    if (errdisconnect) err_quit();
    return;
  }
  /* bad mailfrom unknown check */
  if (bmfunknowncheck())
  {
    err_bmfunknown();
    logline2(3,"bad mailfrom unknown: ",addr.s);
    if (errdisconnect) err_quit();
    return;
  }

  /* NOBOUNCE check */
  if (!addr.s[0] || !str_diff("#@[]", addr.s))
  {
    bounceflag = 1;
    if (nobounce)
    {
      err_554msg("RFC2821 bounces are administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
  }

  /* Sanity checks */
  if (sanitycheck && !bounceflag)
  {
    /* Invalid Mailfrom */
    if ((i=byte_rchr(addr.s,addr.len,'@')) >= addr.len)
    {
      err_554msg("mailfrom without @ is administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    if (i == 0 || addr.s[i+1] == '\0') {
      err_554msg("mailfrom without user or domain part is "
        "administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    /* No '.' in domain.TLD */
    if ((j = byte_rchr(addr.s+i, addr.len-i, '.')) >= addr.len-i) {
      err_554msg("mailfrom without . in domain part is "
        "administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    /* check tld length */
    j = addr.len-(i+1+j+1);
    if (j < 2 || j > 6)
    {
      /* XXX: This needs adjustment when new TLD's are constituded.
       * OK, now after the candidates are nominated we know new TLD's
       * may contain up to six characters.
       */
      err_554msg("mailfrom without country or top level domain is "
        "administratively denied");
      if (errdisconnect) err_quit();
      return;
     }
  }

  /* relay mail from check (allow relaying based on evelope sender address) */
  if (!relayclient) {
    if (rmfcheck()) {
      relayclient = "";
      if (!env_put("RELAYCLIENT=")) die_nomem();
      logline(4,"relaying allowed via relaymailfrom");
    }
  }

  /* Check RBL only if relayclient is not set */
  if (rblok && !relayclient)
  {
    switch(rblcheck(remoteip, &rblname, rbloh))
    {
      case 2: /* soft error lookup */
        /*
         * continue if  RBL DNS has a problem. if a RBL is unreachable
         * we dont want to fail. accept message anyway. a false negative
         * is better in this case than rejecting every message just
         * because one RBL failed. play safe, might be an important mail.
         */
        break;
      case 1: /* host is listed in RBL */
        err_rbl(rblname);
        if (errdisconnect) err_quit();
        return;
      default: /* ok, go ahead */
        logline(4,"RBL checking completed");
        break;
    }
  }

  /* return MX check */
  if (returnmxcheck && !bounceflag)
  {
    if ((i=byte_rchr(addr.s,addr.len,'@')) < addr.len)
      switch (badmxcheck(&addr.s[i+1]))
      {
	case 0:
	  break; /* valid */
	case DNS_SOFT:
	  err_dns();
	  logline(3,"refused mailfrom because return MX lookup "
            "failed temporarly");
	  if (errdisconnect) err_quit();
	  return;
	case DNS_HARD:
	default:
	  err_554msg("refused mailfrom because return MX does not exist");
	  if (errdisconnect) err_quit();
	  return;
      }
  }

  /* check if sender exists in ldap */
  if (sendercheck && !bounceflag) {
    if (!goodmailaddr()) { /* good mail addrs go through anyway */
      logline(4,"sender verify, sender not in goodmailaddr");
      if (addrlocals()) {
	char *s;
	logline(4,"sender verify, sender is local");
        switch (ldaplookup(addr.s, &s)) {
          case 1: /* valid */
	    logline(4,"sender verify OK");
            break;
          case 0: /* invalid */
	    logline2(2, "bad sender: ", addr.s);
            err_554msg(s);
            if (errdisconnect) err_quit();
            return;
          case -1:
          default: /* other error, treat as soft 4xx */
            if (ldapsoftok)
              break;
            err_soft(s);
            if (errdisconnect) err_quit();
            return;
        }
      } else {
        /* not in addrlocals, ldap lookup is useless */
        /* normal mode: let through, it's just an external mail coming in */
        /* loose mode (2): see if sender is in rcpthosts, if no reject here */
        /* strict mode (3): validated sender required so reject in any case */
        if ((sendercheck == 2 && !addrallowed()) || sendercheck == 3) {
          err_554msg("refused mailfrom because valid "
            "local sender address required");
          if (errdisconnect) err_quit();
          return;
        }
      }
    }
  }

  seenmail = 1;
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();
  rcptcount = 0;
  if (loglevel < 4)
    logline2(2,"mail from: ",mailfrom.s);
  out("250 ok\r\n");
}

void smtp_rcpt(char *arg)
{
  if (!seenmail)
  {
    err_wantmail();
    if (errdisconnect) err_quit();
    return;
  }

  /* syntax check */
  if (!addrparse(arg))
  {
    err_syntax();
    logline2(3,"syntax error in 'rcpt to': ",arg);
    if (errdisconnect) err_quit();
    return;
  }

  logline2(4,"rcpt to: ",addr.s);

  /* block stupid and bogus sendwhale bug relay probing */
  /* don't enable this if you use percenthack */
  if (blockrelayprobe && relayprobe()) {
    err_relay();
    logline(3,"'rcpt to' denied, looks like bogus sendwhale bug relay probe");
    if (errdisconnect) err_quit();
    return;
  }

  /* do we block this recipient */
  if (rcptdenied()) {
    err_badrcptto();
    logline2(3,"'rcpt to' denied via badrcptto: ",addr.s);
    if (errdisconnect) err_quit();
    return;
  }

  /* is sender ip allowed to relay */
  if (relayclient) {
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  } else {
    if (!addrallowed()) { 
      err_nogateway();
      logline2(3,"no mail relay for 'rcpt to': ",addr.s);
      if (errdisconnect) err_quit();
      return; 
    }
  }
  ++rcptcount;

  /* maximum recipient limit reached */
  if (maxrcptcount && rcptcount > maxrcptcount) {
    err_maxrcpt();
    logline(3,"message denied because of more 'RCPT TO' than "
      "allowed by MAXRCPTCOUNT");
    if (errdisconnect) err_quit();
    return;
  }

  /* only one recipient for bounce messages */
  if (rcptcount > 1 && (!mailfrom.s[0] || !str_diff("#@[]", mailfrom.s))) {
    err_badbounce();
    logline(3,"bounce message denied because it has more than one recipient");
    if (errdisconnect) err_quit();
    return;
  }

  /* check if recipient exists in ldap */
  if (rcptcheck) {
    if (!goodmailaddr()) {
      logline(4,"recipient verify, recipient not in goodmailaddr");
      if (addrlocals()) {
	char *s;
	logline(4,"recipient verify, recipient is local");
        switch (ldaplookup(addr.s, &s)) {
          case 1: /* valid */
	    logline(4,"recipient verify OK");
            break;
          case 0: /* invalid */
	    logline2(2, "bad recipient: ", addr.s);
            err_554msg(s);
            if (errdisconnect) err_quit();
            return;
          case -1:
          default: /* other error, treat as soft 4xx */
            if (ldapsoftok)
              break;
            err_soft(s);
            if (errdisconnect) err_quit();
            return;
        }
      } /* else this is relaying, don't do anything */
    }
  }

  if (loglevel < 4)
    logline2(2,"rcpt to: ",addr.s);
  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();
  if (tarpitcount && tarpitdelay && rcptcount >= tarpitcount) {
    logline(3,"tarpitting");
    while (sleep(tarpitdelay));
  }
  out("250 ok\r\n");
}

#ifdef DATA_COMPRESS
z_stream stream;
char zbuf[4096];
int wantcomp = 0;
int compdata = 0;

int compression_init(void)
{
  compdata = 1;
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_in = 0;
  stream.next_in = zbuf;
  if (inflateInit(&stream) != Z_OK) {
    out("451 Initalizing data compression failed: ");
    out(stream.msg); out(" #(4.3.0)\r\n"); flush();
    return -1;
  }
  return 0;
}
int compression_done(void)
{
  char num[FMT_ULONG + 1];
  int r;

  compdata = 0;
  if (stream.avail_out != sizeof(zbuf)) {
    /* there is some left data, ignore */
  }
  if (inflateEnd(&stream) != Z_OK) {
    out("451 Finishing data compression failed: ");
    out(stream.msg); out(" #(4.3.0)\r\n"); flush();
    return -1;
  }
  r = 100 - (int)(100.0*stream.total_in/stream.total_out);
  if (r < 0) {
    num[0] = '-';
    r *= -1;
  } else
    num[0] = ' ';
  num[fmt_uint(num+1,r)+1] = 0;
  logpid(3);
  logstring(3,"DDC saved ");
  logstring(3,num);
  logstring(3," percent");
  logflush(3);
  return 0;
}
#endif

int saferead(int fd,void *buf,int len)
{
  int r;
  flush();
#ifdef DATA_COMPRESS
  if (compdata) {
    stream.avail_out = len;
    stream.next_out = buf;
    do {
      if (stream.avail_in == 0) {
#ifdef TLS_SMTPD
	if (ssl)
	  r = ssl_timeoutread(timeout,fd,zbuf,sizeof(zbuf));
	else
#endif
	r = timeoutread(timeout,fd,zbuf,sizeof(zbuf));
	if (r == -1) if (errno == error_timeout) die_alarm();
	if (r <= 0) die_read();
	stream.avail_in = r;
	stream.next_in = zbuf;
      }
      r = inflate(&stream, 0);
      switch (r) {
      case Z_OK:
	if (stream.avail_out == 0)
	  return len;
	break;
      case Z_STREAM_END:
	compdata = 0;
	return len - stream.avail_out;
      default:
	out("451 Receiving compressed data failed: ");
	out(stream.msg); out(" #(4.3.0)\r\n");
	logline2(1, "compressed data read failed: ", stream.msg);
	flush();
	die_read();
      }
      if (stream.avail_out == (unsigned int)len) continue;
      return len - stream.avail_out;
    } while (1);
  }
#endif
#ifdef TLS_SMTPD
  if (ssl)
    r = ssl_timeoutread(timeout,fd,buf,len);
  else
#endif
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

unsigned long bytestooverflow = 0;
unsigned long bytesreceived = 0;

void put(const char *ch)
{
#ifdef SMTPEXECCHECK
  execcheck_put(&qqt, ch);
#endif
  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
  ++bytesreceived;
}

void blast(unsigned int *hops)
{
  char ch;
  int state;
  int flaginheader;
  unsigned int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */
 
  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
      }
      ++pos;
      if (pos > MAXLINELEN) oversizedline();
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    switch(state) {
      case 0:
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 4; continue; }
        break;
      case 1: /* \r\n */
        if (ch == '\n') straynewline();
        if (ch == '.') { state = 2; continue; }
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 2: /* \r\n + . */
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 3; continue; }
        state = 0;
        break;
      case 3: /* \r\n + .\r */
        if (ch == '\n') return;
        put(".");
        put("\r");
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 4: /* + \r */
        if (ch == '\n') { state = 1; break; }
        if (ch != '\r') { put("\r"); state = 0; }
    }
    put(&ch);
  }
}

void acceptmessage(unsigned long qp)
{
  static char buf[FMT_ULONG];

  datetime_sec when;
  when = now();
  out("250 ok ");
  buf[fmt_ulong(buf,(unsigned long) when)] = 0;
  out(buf);
  logpid(2); logstring(2,"message queued: "); logstring(2,buf);
  out(" qp ");
  buf[fmt_ulong(buf,qp)] = 0;
  out(buf);
  out(" by ");
  out(me.s);
  out("\r\n");
  logstring(2," qp "); logstring(2,buf);
  buf[fmt_ulong(buf, bytesreceived)] = 0;
  logstring(2, " size ");
  logstring(2, buf);
  logstring(2, " bytes");
  logflush(2);
}

#ifdef TLS_SMTPD
stralloc protocolinfo = {0};
#endif

void smtp_data(char *arg) {
  unsigned int hops;
  unsigned long qp;
  const char *qqx;

  ldaplookupdone();
  if (!seenmail) {
    err_wantmail();
    if (errdisconnect) err_quit();
    return;
  }
  if (!rcptto.len) {
    err_wantrcpt();
    if (errdisconnect) err_quit();
    return;
  }
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;
#ifdef SMTPEXECCHECK
  execcheck_start();
#endif
  if (qmail_open(&qqt) == -1) {
    err_qqt();
    logline(1,"failed to start qmail-queue");
    return;
  }
  qp = qmail_qp(&qqt);
  out("354 go ahead punk, make my day\r\n"); logline(4,"go ahead");
  rblheader(&qqt);

#ifdef TLS_SMTPD
  if(ssl){
    if (!stralloc_copys(&protocolinfo,
       SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)))) die_nomem();
#ifdef DATA_COMPRESS
    if (wantcomp) {
      if (!stralloc_cats(&protocolinfo, " encrypted compressed SMTP"))
	die_nomem();
    } else
#endif
    if (!stralloc_cats(&protocolinfo, " encrypted SMTP")) die_nomem();
  } else {
#ifdef DATA_COMPRESS
    if (wantcomp) {
      if (!stralloc_copys(&protocolinfo,"compressed SMTP")) die_nomem();
    } else
#endif
    if (!stralloc_copys(&protocolinfo,"SMTP")) die_nomem();
  }
  if (!stralloc_0(&protocolinfo)) die_nomem();
  received(&qqt,protocolinfo.s,local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
#else 
#ifdef DATA_COMPRESS
  if (wantcomp)
    received(&qqt,"compressed SMTP",local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
  else
#endif
    received(&qqt,"SMTP",local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
#endif

#ifdef DATA_COMPRESS
  if (wantcomp) { if (compression_init() != 0) return; }
#endif
  blast(&hops);
#ifdef DATA_COMPRESS
  if (wantcomp) { if (compression_done() != 0) return; }
#endif

  hops = (hops >= MAXHOPS);
  if (hops)
    qmail_fail(&qqt);
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);
 
  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) {
    out("554 too many hops, this message is looping (#5.4.6)\r\n");
    logline(3,"too many hops, message is looping");
    if (errdisconnect) err_quit();
    return;
  }
  if (databytes) if (!bytestooverflow) {
    out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n");
    logline(3,"datasize limit exceeded");
    if (errdisconnect) err_quit();
    return;
  }
#ifdef SMTPEXECCHECK
  if (execcheck_flag()) {
    out("552 we don't accept email with this MIME content (#5.3.4)\r\n");
    logline(3,"bad MIME attachement detected");
    if (errdisconnect) err_quit();
    return;
  }
#endif

  logpid(1);
  if (*qqx == 'D') {
    out("554 "); logstring(1,"message permanently not accepted because: ");
  } else {
    out("451 "); logstring(1,"message temporarly not accepted because: ");
  }
  out(qqx + 1);
  logstring(1,qqx + 1); logflush(1);
  out("\r\n");
}

#ifdef DATA_COMPRESS
void smtp_dataz(char *arg)
{
  wantcomp = 1;
  smtp_data((char *)0);
}
#endif

stralloc line = {0};

void smtp_auth(char *arg)
{
  struct call cct;
  char *type;
  const char *status;

  if (!flagauth) {
    err_unimpl("AUTH without STARTTLS");
    return;
  }
  if (flagauthok) {
    out("503 you are already authenticated\r\n");
    logline(3,"reauthentication attempt rejected");
    if (errdisconnect) err_quit();
    return;
  }
#ifdef TLS_SMTPD
  if (needssl && !ssl) {
    out("538 Encryption required for requested authentication mechanism");
    logline(3,"TLS encryption required for authentication");
    if (errdisconnect) err_quit();
    return;
  }
#endif
  type = arg;
  while (*arg != '\0' && *arg != ' ') ++arg;
  if (*arg) {
    *arg++ = '\0';
    while (*arg == ' ') ++arg;
  }
  
  if (case_diffs(type, "login") == 0) {
    logline(4,"auth login");
    if (call_open(&cct, "bin/auth_smtp", 30, 1) == -1) goto fail;
    call_puts(&cct, "login"); call_put(&cct, "", 1);
    if (*arg) {
      call_puts(&cct, arg); call_put(&cct, "", 1);
    } else {
      out("334 VXNlcm5hbWU6\r\n"); flush(); /* base64 for 'Username:' */
      if (call_getln(&ssin, &line) == -1) die_read();
      call_puts(&cct, line.s); call_put(&cct, "", 1);
    }
    out("334 UGFzc3dvcmQ6\r\n"); flush(); /* base64 for 'Password:' */
    if (call_getln(&ssin, &line) == -1) die_read();
    call_puts(&cct, line.s); call_putflush(&cct, "", 1);
  } else if (case_diffs(type, "plain") == 0) {
    logline(4,"auth plain");
    if (call_open(&cct, "bin/auth_smtp", 30, 1) == -1) goto fail;
    call_puts(&cct, "plain"); call_put(&cct, "", 1);
    if (*arg) {
      call_puts(&cct, arg); call_putflush(&cct, "", 1);
    } else {
      out("334 \r\n"); flush();
      if (call_getln(&ssin, &line) == -1) die_read();
      call_puts(&cct, line.s); call_putflush(&cct, "", 1);
    }
  } else {
    out("504 authentication type not supported\r\n");
    logstring(3,"authentication type ");
    logstring(3,type);
    logstring(3,": not supported");
    logflush(3);
    if (errdisconnect) err_quit();
    return;
  }
fail:
  status = auth_close(&cct, &line, authprepend);
  switch (*status) {
  case '2':
    flagauthok = 1;
    remoteinfo = line.s;
    out(status);
    logline2(2,"authentication success, user ", remoteinfo);
    break;
  case '4':
  case '5':
    sleep(1);
    out(status); flush();
    logline2(3, "authentication failed: ", status + 4);
    sleep(4);
    if (errdisconnect) err_quit();
    break;
  }
}

#ifdef TLS_SMTPD
RSA *tmp_rsa_cb(SSL *s,int export,int keylength) 
{
  RSA* rsa;
  BIO* in;

  if (!export || keylength == 512)
   if ((in=BIO_new(BIO_s_file_internal())))
    if (BIO_read_filename(in,"control/rsa512.pem") > 0)
     if ((rsa=PEM_read_bio_RSAPrivateKey(in,NULL,NULL,NULL)))
      return rsa;
  return (RSA_generate_key(export?keylength:512,RSA_F4,NULL,NULL));
}

void smtp_tls(char *arg) 
{
  SSL_CTX *ctx;

  if (sslcert.s == 0 || *sslcert.s == '\0') {
    err_unimpl("STARTTLS");
    return;
  }

  if (*arg)
  {
    out("501 Syntax error (no parameters allowed) (#5.5.4)\r\n");
    logline(3,"aborting TLS negotiations, no parameters to starttls allowed");
    return;
  }

  SSLeay_add_ssl_algorithms();
  if(!(ctx=SSL_CTX_new(SSLv23_server_method())))
  {
    out("454 TLS not available: unable to initialize ctx (#4.3.0)\r\n"); 
    logline(3,"aborting TLS negotiations, "
      "unable to initialize local SSL context");
    return;
  }
  if(!SSL_CTX_use_RSAPrivateKey_file(ctx, sslcert.s, SSL_FILETYPE_PEM))
  {
    out("454 TLS not available: missing RSA private key (#4.3.0)\r\n");
    logline2(3,"aborting TLS negotiations, "
      "RSA private key invalid or unable to read ", sslcert.s);
    return;
  }
  if(!SSL_CTX_use_certificate_chain_file(ctx, sslcert.s))
  {
    out("454 TLS not available: missing certificate (#4.3.0)\r\n"); 
    logline2(3,"aborting TLS negotiations, "
      "local cert invalid or unable to read ", sslcert.s);
    return;
  }
  SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
 
  out("220 ready for tls\r\n"); flush();

  if(!(ssl=SSL_new(ctx))) 
  {
    logline(3,"aborting TLS connection, unable to set up SSL session");
    die_read();
  }
  SSL_set_rfd(ssl,substdio_fileno(&ssin));
  SSL_set_wfd(ssl,substdio_fileno(&ssout));
  if(SSL_accept(ssl)<=0)
  {
    logline(3,"aborting TLS connection, unable to finish SSL accept");
    die_read();
  }
  //substdio_fdbuf(&ssout,SSL_write,ssl,ssoutbuf,sizeof(ssoutbuf));

  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  dohelo(remotehost);
}
#endif

void cleanup(void)
{
	ldaplookupdone();
}

void err_503or421(char *arg)
{
  if (greeting421)
    out("421 Service temporarily not available (#4.3.2)\r\n");
  else
    out("503 bad sequence of commands (#5.5.1)\r\n");
  if (errdisconnect) err_quit();
}
void err_badcommand(char *arg)
{
  out("503 bad sequence of commands (#5.5.1)\r\n");
}

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
#ifdef TLS_SMTPD
, { "starttls", smtp_tls, flush }
#endif
#ifdef DATA_COMPRESS
, { "dataz", smtp_dataz, flush }
#endif
, { "auth", smtp_auth, flush }
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { 0, err_unimpl, flush }
} ;

struct commands smtprestricted[] = {
  { "quit", smtp_quit, flush }
, { "helo", err_503or421, flush }
, { "ehlo", err_503or421, flush }
, { 0, err_badcommand, flush }
};

int main(int argc, char **argv)
{
#ifdef TLS_SMTPD
  sig_alarmcatch(sigalrm);
#endif
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  if (ipme_init() != 1) die_ipme();
  if (greeting550 || greeting421) {
    if (!stralloc_copys(&greeting,greeting550 ? greeting550 : greeting421))
      die_nomem();
    timeout = 20; /* reduce timeout so the abuser is kicked out faster */
    if (greeting.len == 0 && greeting550)
      stralloc_copys(&greeting,
	  "Sorry, your mail was administratively denied. (#5.7.1)");
    else if (greeting.len == 0 && greeting421)
      stralloc_copys(&greeting,
	  "Service temporarily not available (#4.3.2)");

    smtp_line(greeting550 ? "554 " : "421 ");
    if (errdisconnect) err_quit();
    if (commands(&ssin,smtprestricted) == 0) die_read();
    die_nomem();
  }
  smtp_greet("220 ");
  if (commands(&ssin,smtpcommands) == 0) die_read();
  die_nomem();
  /* NOTREACHED */
  return 1;
}

