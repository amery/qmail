#include "env.h"
#include "str.h"

extern /*@null@*/char *env_get(s)
const char *s;
{
  unsigned int i;
  unsigned int slen;
  char *envi;
 
  slen = str_len(s);
  for (i = 0;(envi = environ[i]);++i)
    if ((!str_diffn(s,envi,slen)) && (envi[slen] == '='))
      return envi + slen + 1;
  return 0;
}

extern char *env_pick(void)
{
  return environ[0];
}

extern const char *env_findeq(s)
const char *s;
{
  for (;*s;++s)
    if (*s == '=')
      return s;
  return 0;
}
