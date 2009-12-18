/*
 * Copyright (c) 2002-2004 Andre Oppermann,
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
#include "alloc.h"
#include "control.h"
#include "dns.h"
#include "env.h"
#include "ipalloc.h"
#include "qmail.h"
#include "str.h"
#include "stralloc.h"

#include "rbl.h"

static stralloc rblmessage = {0};
int rblprintheader = 0;

/* functions borrowed from qmail-smtpd.c */
extern void safeput();
extern void die_nomem();

extern void logpid();
extern void logline();
extern void logstring();
extern void logflush();

void rblheader(struct qmail *qqt)
{
  if (!rblprintheader) return;
  /* rblmessage is safe because it does not contain any remote info */
  if (rblmessage.s) qmail_put(qqt,rblmessage.s,rblmessage.len);
}

struct rbl {
  char *baseaddr;
  char *action;
  char *matchon;
  char *message;
} *rbl;

unsigned int numrbl;

static stralloc ip_reverse = {0};
static stralloc rbl_tmp = {0};

static int rbl_start(const char *remoteip)
{
  unsigned int i;
  unsigned int j;
  const char *ip_env;

  ip_env = remoteip;
  if (!ip_env) ip_env = "";

  if (!stralloc_copys(&ip_reverse,"")) die_nomem();

  i = str_len(ip_env);
  while (i) {
    for (j = i;j > 0;--j) {
      if (ip_env[j - 1] == '.') break;
      if (ip_env[j - 1] == ':') return 0; /* no IPv6 */
    }
    if (!stralloc_catb(&ip_reverse,ip_env + j,i - j)) die_nomem();
    if (!stralloc_cats(&ip_reverse,".")) die_nomem();
    if (!j) break;
    i = j - 1;
  }
  return 1;
}

static char ipstr[IPFMT];

static int rbl_lookup(char *base, char *matchon)
{
  ipalloc rblsa = {0};
  unsigned int i;

  if (!*base) return 2;

  if (!stralloc_copy(&rbl_tmp,&ip_reverse)) die_nomem();
  if (!stralloc_cats(&rbl_tmp,base)) die_nomem();

  switch (dns_ip(&rblsa,&rbl_tmp)) {
    case DNS_MEM:
    case DNS_SOFT:
      return 2; /* soft error */
    case DNS_HARD:
      return 0; /* found no match */
    default: /* found match */
      if (!str_diff("any", matchon))
        return 1;
      for (i = 0;i < rblsa.len;++i)
      {
	ipstr[ip_fmt(ipstr,&rblsa.ix[i].ip)]=0;
	if (!str_diff(ipstr, matchon)) return 1;
      }
      return 0; /* found match but ignored */
  }
  return 1; /* should never get here */
}

void rbladdheader(char *base, char *matchon, char *message)
{
  /* all of base, matchon and message can be trusted because these
     are under our control */
  rblprintheader = 1;
  if(!stralloc_cats(&rblmessage, "X-RBL: (")) die_nomem();
  if(!stralloc_cats(&rblmessage, base)) die_nomem();
  if(!stralloc_cats(&rblmessage, ") ")) die_nomem();
  if (str_diff("any", matchon)) {
    if(!stralloc_cats(&rblmessage, "matches with ")) die_nomem();
    if(!stralloc_cats(&rblmessage, matchon)) die_nomem();
    if(!stralloc_cats(&rblmessage, " and ")) die_nomem();
  }
  if(!stralloc_cats(&rblmessage, "tells us ")) die_nomem();
  if(!stralloc_cats(&rblmessage, message)) die_nomem();
  if(!stralloc_cats(&rblmessage, "\n")) die_nomem();
}

void
rbllog(int level, const char* baseaddr, const char *msg)
{
	logpid(level);
	logstring(level, "RBL check with '");
	logstring(level, baseaddr);
	logstring(level, "': ");
	logstring(level, msg);
        logflush(level);
}

int rblcheck(const char *remoteip, char** rblname, int rbloh)
{
  int r = 1;
  unsigned int i;

  if(!stralloc_copys(&rblmessage, "")) die_nomem();
  if(!rbl_start(remoteip)) return 0;

  for (i=0; i < numrbl; i++) {
    r = rbl_lookup(rbl[i].baseaddr, rbl[i].matchon);

    if (r == 2) {
      rbllog(3,rbl[i].baseaddr, "temporary DNS error, ignored");
    } else if (r == 1) {
      *rblname = rbl[i].message;
      if (rbloh) {
        rbllog(3,rbl[i].baseaddr, "found match, tag header");
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      }
      if (!str_diff("addheader", rbl[i].action)) {
        rbllog(3,rbl[i].baseaddr, "found match, tag header");
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      } else {
	/* default reject */
        rbllog(2,rbl[i].baseaddr, "found match, reject sender");
	rblprintheader = 0;
	return 1;
      }
    }
    /* continue */
    rbllog(3,rbl[i].baseaddr, "no match found, continue.");
  }
  return 0; /* either tagged, soft error or allowed */
}

stralloc rbldata = {0};

int rblinit(void)
{
  char** x;
  int on;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned int n;

  on = control_readfile(&rbldata,"control/rbllist",0);
  if (on == -1) return on;
  if (!on) return on;

  for(i=0, numrbl=0; i < rbldata.len; ++i)
    if (rbldata.s[i] == '\0')
	++numrbl;

  rbl = (struct rbl*)alloc(numrbl*sizeof(struct rbl));
  if (!rbl) return -1;

  /* line format is "basedomain action matchon message"
     message may have spaces */
  x = (char **)&rbl[0];
  for (i=0, j=0, k=0, n=0; i < rbldata.len; ++i) {
    while (1) {
      /* hop over spaces */
      if (rbldata.s[i] != ' ' && rbldata.s[i] != '\t') break;
      if (rbldata.s[i] == '\0') {
	logline(1, "parse error in rbllist, unexpected end of line");
	return -1;
      }
      i++;
    }
    j = i;
    if (n == 3) {
      /* message */
      x[n] = rbldata.s + j;
      n = 0;
      x = (char **)&rbl[++k];
      while (rbldata.s[i] != '\0') i++;
    } else {
      while (1) {
        /* hop over argument */
        if (rbldata.s[i] == ' ' || rbldata.s[i] == '\t') break;
        if (rbldata.s[i] == '\0') {
	  logline(1, "parse error in rbllist, unexpected end of line");
	  return -1;
        }
        i++;
      }
      rbldata.s[i] = '\0';
      x[n++] = rbldata.s + j;
    }
  }
  if (k != numrbl) {
    logline(1,"parse error in rbllist, unexpected end of file");
    return -1;
  }

  return 1; /* everything fine */
}

