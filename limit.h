#ifndef __LIMIT_H__
#define __LIMIT_H__

#include <limits.h>

/* 
 * we only need the max value for 32bit integers so make sure that we have
 * those available.
 * So we assume ILP32 or I32LP64 based systems which should be the default
 * for unix systems. AFAIK only Cray is ILP64...
 */
#ifndef UINT_MAX
#define UINT_MAX        0xffffffffU     /* max value for an unsigned int */
#endif
#ifndef INT_MAX
#define INT_MAX         0x7fffffff      /* max value for an int */
#endif
#ifndef INT_MIN
#define INT_MIN         (-0x7fffffff-1) /* min value for an int */
#endif

#endif
