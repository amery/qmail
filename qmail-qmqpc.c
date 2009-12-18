#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "substdio.h"
#include "getln.h"
#include "readwrite.h"
#include "exit.h"
#include "stralloc.h"
#include "slurpclose.h"
#include "error.h"
#include "sig.h"
#include "ip.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "auto_qmail.h"
#include "control.h"
#include "fmt.h"
#ifdef QMQP_COMPRESS
#include <zlib.h>
#endif


#ifndef PORT_QMQP /* this is for testing purposes */
#define PORT_QMQP 628
#endif

void die_success(void) { _exit(0); }
void die_perm(void) { _exit(31); }
void nomem(void) { _exit(51); }
void die_read(void) { if (errno == error_nomem) nomem(); _exit(54); }
void die_control(void) { _exit(55); }
void die_socket(void) { _exit(56); }
void die_home(void) { _exit(61); }
void die_temp(void) { _exit(71); }
void die_conn(void) { _exit(74); }
void die_format(void) { _exit(91); }

int timeoutconnect = 60;
int lasterror = 55;
int qmqpfd;

#ifdef QMQP_COMPRESS
z_stream stream;
char zbuf[4096];

void compression_init(void)
{
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_out = sizeof(zbuf);
  stream.next_out = zbuf;
  if (deflateInit(&stream,Z_DEFAULT_COMPRESSION) != Z_OK)
    die_format();
}
void compression_done(void)
{
  int r;

  do {
    r = deflate(&stream,Z_FINISH);
    switch (r) {
    case Z_OK:
      if (stream.avail_out == 0) {
	r = timeoutwrite(60,qmqpfd,zbuf,sizeof(zbuf));
	if (r <= 0) die_conn();
	stream.avail_out = sizeof(zbuf);
	stream.next_out = zbuf;
	r = Z_OK;
      }
      break;
    case Z_STREAM_END:
      break;
    default:
      die_format();
    }
  } while (r!=Z_STREAM_END);
  if (stream.avail_out != sizeof(zbuf)) {
    /* write left data */
    r = timeoutwrite(60,qmqpfd,zbuf,sizeof(zbuf)-stream.avail_out);
    if (r <= 0) die_conn();
  }
  if (deflateEnd(&stream) != Z_OK) die_format();
}
#endif

int saferead(int fd, void *buf, int len)
{
  int r;
  r = timeoutread(60,qmqpfd,buf,len);
  if (r <= 0) die_conn();
  return r;
}
int safewrite(int fd, void *buf, int len)
{
  int r;
#ifdef QMQP_COMPRESS
  stream.avail_in = len;
  stream.next_in = buf;
  do {
    r = deflate(&stream, 0);
    switch (r) {
    case Z_OK:
      if (stream.avail_out == 0) {
	r = timeoutwrite(60,qmqpfd,zbuf,sizeof(zbuf));
	if (r <= 0) die_conn();
	stream.avail_out = sizeof(zbuf);
	stream.next_out = zbuf;
      }
      break;
    default:
      die_format();
    }
  } while (stream.avail_in != 0);
  return len;
#endif
  r = timeoutwrite(60,qmqpfd,buf,len);
  if (r <= 0) die_conn();
  return r;
}

char buf[1024];
substdio to = SUBSTDIO_FDBUF(safewrite,-1,buf,sizeof buf);
substdio from = SUBSTDIO_FDBUF(saferead,-1,buf,sizeof buf);
substdio envelope = SUBSTDIO_FDBUF(subread,1,buf,sizeof buf);
/* WARNING: can use only one of these at a time! */

stralloc beforemessage = {0};
stralloc message = {0};
stralloc aftermessage = {0};

char strnum[FMT_ULONG];
stralloc line = {0};

void getmess()
{
  int match;

  if (slurpclose(0,&message,1024) == -1) die_read();

  strnum[fmt_uint(strnum,message.len)] = 0;
  if (!stralloc_copys(&beforemessage,strnum)) nomem();
  if (!stralloc_cats(&beforemessage,":")) nomem();
  if (!stralloc_copys(&aftermessage,",")) nomem();

  if (getln(&envelope,&line,&match,'\0') == -1) die_read();
  if (!match) die_format();
  if (line.len < 2) die_format();
  if (line.s[0] != 'F') die_format();

  strnum[fmt_uint(strnum,line.len - 2)] = 0;
  if (!stralloc_cats(&aftermessage,strnum)) nomem();
  if (!stralloc_cats(&aftermessage,":")) nomem();
  if (!stralloc_catb(&aftermessage,line.s + 1,line.len - 2)) nomem();
  if (!stralloc_cats(&aftermessage,",")) nomem();

  for (;;) {
    if (getln(&envelope,&line,&match,'\0') == -1) die_read();
    if (!match) die_format();
    if (line.len < 2) break;
    if (line.s[0] != 'T') die_format();

    strnum[fmt_uint(strnum,line.len - 2)] = 0;
    if (!stralloc_cats(&aftermessage,strnum)) nomem();
    if (!stralloc_cats(&aftermessage,":")) nomem();
    if (!stralloc_catb(&aftermessage,line.s + 1,line.len - 2)) nomem();
    if (!stralloc_cats(&aftermessage,",")) nomem();
  }
}

struct ip_address outip;

void doit(server)
char *server;
{
  struct ip_address ip;
  char ch;

  if (!ip_scan(server,&ip)) return;

  qmqpfd = socket(AF_INET,SOCK_STREAM,0);
  if (qmqpfd == -1) die_socket();

  if (timeoutconn(qmqpfd,&ip,&outip,PORT_QMQP,timeoutconnect) != 0) {
    lasterror = 73;
    if (errno == error_timeout) lasterror = 72;
    close(qmqpfd);
    return;
  }

#ifdef QMQP_COMPRESS
  compression_init();
#endif
  strnum[fmt_uint(strnum, 
         (beforemessage.len + message.len + aftermessage.len))] = 0;
  substdio_puts(&to,strnum);
  substdio_puts(&to,":");
  substdio_put(&to,beforemessage.s,beforemessage.len);
  substdio_put(&to,message.s,message.len);
  substdio_put(&to,aftermessage.s,aftermessage.len);
  substdio_puts(&to,",");
  substdio_flush(&to);
#ifdef QMQP_COMPRESS
  compression_done();
#endif

  for (;;) {
    substdio_get(&from,&ch,1);
    if (ch == 'K') die_success();
    if (ch == 'Z') die_temp();
    if (ch == 'D') die_perm();
  }
}

stralloc servers = {0};
stralloc outgoingip = {0};

#include "dns.h"
#include "ipalloc.h"

ipalloc ia = {0};

int main(argc,argv)
int argc;
char **argv;
{
  unsigned int i;
  unsigned int j;

  sig_pipeignore();

  if (chdir(auto_qmail) == -1) die_home();
  if (control_init() == -1) die_control();
  if ( argv[1] ) {
    char temp[IPFMT];
    if (!stralloc_copys(&servers,argv[1])) nomem();
    dns_init(0);
    switch (dns_ip(&ia,&servers)) {
      case DNS_HARD: die_perm();
      case DNS_SOFT: die_temp();
      case DNS_MEM: nomem();
    }

    temp[ip_fmt(temp,&ia.ix[0].ip)]=0;
    if (!stralloc_copys(&servers, temp)) nomem();
    if (!stralloc_0(&servers)) nomem();
  } else
  if (control_readfile(&servers,"control/qmqpservers",0) != 1) die_control();

  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    die_control();

  if (control_rldef(&outgoingip, "control/qmqpcip", 0, "0.0.0.0") == -1)
	  die_control();
  if (!stralloc_0(&outgoingip)) nomem();
  if (!ip_scan(outgoingip.s,&outip)) die_control();

  getmess();

  i = 0;
  for (j = 0;j < servers.len;++j)
    if (!servers.s[j]) {
      doit(servers.s + i);
      i = j + 1;
    }

  return lasterror;
}
