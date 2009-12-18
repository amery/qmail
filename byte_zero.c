#include "byte.h"

void byte_zero(s,n)
void *s;
register unsigned int n;
{
  char *S = (char *)s;
  for (;;) {
    if (!n) break; *S++ = 0; --n;
    if (!n) break; *S++ = 0; --n;
    if (!n) break; *S++ = 0; --n;
    if (!n) break; *S++ = 0; --n;
  }
}
