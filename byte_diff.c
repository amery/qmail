#include "byte.h"

int byte_diff(s,n,t)
const void *s;
register unsigned int n;
const void *t;
{
  register const char *S = (const char *)s;
  register const char *T = (const char *)t;

  for (;;) {
    if (!n) return 0; if (*S != *T) break; ++S; ++T; --n;
    if (!n) return 0; if (*S != *T) break; ++S; ++T; --n;
    if (!n) return 0; if (*S != *T) break; ++S; ++T; --n;
    if (!n) return 0; if (*S != *T) break; ++S; ++T; --n;
  }
  return ((int)(unsigned int)(unsigned char) *S)
       - ((int)(unsigned int)(unsigned char) *T);
}
