#ifndef COMMANDS_H
#define COMMANDS_H

#include "substdio.h"

struct commands {
  const char *text;
  void (*fun)();
  void (*flush)();
} ;

extern int commands(substdio *, struct commands *);

#endif
