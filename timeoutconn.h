#ifndef TIMEOUTCONN_H
#define TIMEOUTCONN_H

struct ip_address;

extern int timeoutconn(int, struct ip_address *,
    struct ip_address *, unsigned int, int);

#endif
