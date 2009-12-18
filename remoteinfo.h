#ifndef REMOTEINFO_H
#define REMOTEINFO_H

struct ip_address;

extern char *remoteinfo_get(struct  ip_address *, unsigned long,
    struct ip_address *, unsigned long, int);

#endif
