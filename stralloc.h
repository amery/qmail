#ifndef STRALLOC_H
#define STRALLOC_H

#include "gen_alloc.h"

GEN_ALLOC_typedef(stralloc,char,s,len,a)

extern int stralloc_ready(stralloc *, unsigned int);
extern int stralloc_readyplus(stralloc *, unsigned int);
extern int stralloc_copy(stralloc *, stralloc *);
extern int stralloc_cat(stralloc *, stralloc *);
extern int stralloc_copys(stralloc *, const char *);
extern int stralloc_cats(stralloc *, const char *);
extern int stralloc_copyb(stralloc *, const char *, unsigned int);
extern int stralloc_catb(stralloc *, const char *, unsigned int);
extern int stralloc_append(stralloc *, const char *); /* beware: this takes a pointer to 1 char */
extern int stralloc_starts(stralloc *, const char *);

#define stralloc_0(sa) stralloc_append(sa,"")

#endif
