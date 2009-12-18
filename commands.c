#include "commands.h"
#include "substdio.h"
#include "stralloc.h"
#include "str.h"
#include "case.h"

static stralloc cmd = {0};

int commands(ss,c)
substdio *ss;
struct commands *c;
{
  int i;
  unsigned int n;
  char *arg;

  for (;;) {
    if (!stralloc_copys(&cmd,"")) return -1;

    for (;;) {
      if (!stralloc_readyplus(&cmd,1)) return -1;
      i = substdio_get(ss,cmd.s + cmd.len,1);
      if (i != 1) return i;
      if (cmd.s[cmd.len] == '\n') break;
      ++cmd.len;
    }

    if (cmd.len > 0) if (cmd.s[cmd.len - 1] == '\r') --cmd.len;

    cmd.s[cmd.len] = 0;

    n = str_chr(cmd.s,' ');
    arg = cmd.s + n;
    while (*arg == ' ') ++arg;
    cmd.s[n] = 0;

    for (n = 0;c[n].text;++n) if (case_equals(c[n].text,cmd.s)) break;
    c[n].fun(arg);
    if (c[n].flush) c[n].flush();
  }
}
