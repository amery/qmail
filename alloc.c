#include <stdlib.h>
#include "alloc.h"
#include "error.h"

/*@null@*//*@out@*/void *alloc(n)
unsigned int n;
{
  void *x;
  x = malloc(n);
  if (!x) errno = error_nomem;
  return x;
}

void alloc_free(x)
void *x;
{
  free(x);
}
