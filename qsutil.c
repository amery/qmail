#include <unistd.h>
#include "stralloc.h"
#include "readwrite.h"
#include "substdio.h"
#include "qsutil.h"

static stralloc foo = {0};

static char errbuf[1];
static struct substdio sserr = SUBSTDIO_FDBUF(subwrite,0,errbuf,1);

void logsa(sa) stralloc *sa; {
 substdio_putflush(&sserr,sa->s,sa->len); }
void log1(s1) const char *s1; {
 substdio_putsflush(&sserr,s1); }
void log2(s1,s2) const char *s1; const char *s2; {
 substdio_putsflush(&sserr,s1);
 substdio_putsflush(&sserr,s2); }
void log3(s1,s2,s3) const char *s1; const char *s2; const char *s3; {
 substdio_putsflush(&sserr,s1);
 substdio_putsflush(&sserr,s2);
 substdio_putsflush(&sserr,s3); }
void nomem(void) { log1("alert: out of memory, sleeping...\n"); sleep(10); }

void pausedir(dir) const char *dir;
{ log3("alert: unable to opendir ",dir,", sleeping...\n"); sleep(10); }

static int issafe(ch) char ch;
{
 if (ch == '%') return 0; /* general principle: allman's code is crap */
 if (ch < 33) return 0;
 if (ch > 126) return 0;
 return 1;
}

void logsafe(s) const char *s;
{
 unsigned int i;
 while (!stralloc_copys(&foo,s)) nomem();
 for (i = 0; i < foo.len;++i)
   if (foo.s[i] == '\n')
     foo.s[i] = '/';
   else
     if (!issafe(foo.s[i]))
       foo.s[i] = '_';
 logsa(&foo);
}
