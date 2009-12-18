#include "byte.h"

void byte_copyr(to,n,from)
void *to;
register unsigned int n;
const void *from;
{
  register char *t = (char *)to;
  register const char *f = (const char *)from;

  t += n;
  f += n;
  for (;;) {
    if (!n) return; *--t = *--f; --n;
    if (!n) return; *--t = *--f; --n;
    if (!n) return; *--t = *--f; --n;
    if (!n) return; *--t = *--f; --n;
  }
}
