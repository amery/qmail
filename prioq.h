#ifndef PRIOQ_H
#define PRIOQ_H

#include "datetime.h"
#include "gen_alloc.h"

struct prioq_elt { datetime_sec dt; unsigned long id; } ;

GEN_ALLOC_typedef(prioq,struct prioq_elt,p,len,a)

extern int prioq_insert(prioq *, struct prioq_elt *);
extern int prioq_min(prioq *, struct prioq_elt *);
extern void prioq_delmin(prioq *);

#endif
