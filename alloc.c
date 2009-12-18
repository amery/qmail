#include <stdlib.h>
#include "alloc.h"
#include "error.h"

#define ALIGNMENT 16 /* XXX: assuming that this alignment is enough */
#define SPACE 4096 /* must be multiple of ALIGNMENT */

typedef union { char irrelevant[ALIGNMENT]; double d; } aligned;
static aligned realspace[SPACE / ALIGNMENT];
#define space ((char *) realspace)
static unsigned int avail = SPACE; /* multiple of ALIGNMENT; 0<=avail<=SPACE */

/*@null@*//*@out@*/void *alloc(n)
unsigned int n;
{
  void *x;
  n = ALIGNMENT + n - (n & (ALIGNMENT - 1)); /* XXX: could overflow */
  if (n <= avail) { avail -= n; return space + avail; }
  x = malloc(n);
  if (!x) errno = error_nomem;
  return x;
}

void alloc_free(x)
void *x;
{
  if ((char *)x >= space)
    if ((char *)x < space + SPACE)
      return; /* XXX: assuming that pointers are flat */
  free(x);
}
