#ifndef READSUBDIR_H
#define READSUBDIR_H

#include "direntry.h"

typedef struct readsubdir
 {
  DIR *dir;
  unsigned int pos;
  const char *name;
  void (*pause)();
 }
readsubdir;

extern void readsubdir_init(readsubdir *, const char *, void (*)());
extern int readsubdir_next(readsubdir *, unsigned long *);

#define READSUBDIR_NAMELEN 10

#endif
