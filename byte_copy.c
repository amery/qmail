#include "byte.h"

void byte_copy(to,n,from)
void *to;
register unsigned int n;
const void *from;
{
  register char *t = (char *)to;
  register const char *f = (const char *)from;
  for (;;) {
    if (!n) return; *t++ = *f++; --n;
    if (!n) return; *t++ = *f++; --n;
    if (!n) return; *t++ = *f++; --n;
    if (!n) return; *t++ = *f++; --n;
  }
}
