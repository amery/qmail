#include "byte.h"
#include "str.h"
#include "stralloc.h"

int stralloc_cats(sa,s)
stralloc *sa;
const char *s;
{
  return stralloc_catb(sa,s,str_len(s));
}
