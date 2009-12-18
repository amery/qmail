#ifndef TRIGGER_H
#define TRIGGER_H

#include "select.h"

extern void trigger_set(void);
extern void trigger_selprep(int *, fd_set *);
extern int trigger_pulled(fd_set *);

#endif
