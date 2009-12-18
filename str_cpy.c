#include "str.h"

unsigned int str_copy(s,t)
register char *s;
register const char *t;
{
  register unsigned int len;

  len = 0;
  for (;;) {
    if (!(*s = *t)) return len; ++s; ++t; ++len;
    if (!(*s = *t)) return len; ++s; ++t; ++len;
    if (!(*s = *t)) return len; ++s; ++t; ++len;
    if (!(*s = *t)) return len; ++s; ++t; ++len;
  }
}
