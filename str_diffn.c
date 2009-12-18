#include "str.h"

int str_diffn(s,t,len)
register const char *s;
register const char *t;
unsigned int len;
{
  register char x;

  for (;;) {
    if (!len--) return 0; x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
    if (!len--) return 0; x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
    if (!len--) return 0; x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
    if (!len--) return 0; x = *s; if (x != *t) break; if (!x) break; ++s; ++t;
  }
  return ((int)(unsigned int)(unsigned char) x)
       - ((int)(unsigned int)(unsigned char) *t);
}
