#ifndef CONTROL_H
#define CONTROL_H

#include "stralloc.h"

extern int control_init(void);
extern int control_readline(stralloc *, const char *);
extern int control_rldef(stralloc *, const char *, int, const char *);
extern int control_readint(int *, const char *);
extern int control_readulong(unsigned long *, const char *);
extern int control_readfile(stralloc *, const char *, int);
extern int control_readrawfile(stralloc *, const char *);

#endif
