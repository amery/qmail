#ifndef IPME_H
#define IPME_H

#include "ip.h"
#include "ipalloc.h"

extern ipalloc ipme;

extern int ipme_init(void);
extern int ipme_is(struct ip_address *);

#endif
