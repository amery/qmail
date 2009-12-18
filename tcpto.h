#ifndef TCPTO_H
#define TCPTO_H

struct ip_address;

extern int tcpto(struct ip_address *);
extern void tcpto_err(struct ip_address *, int);
extern void tcpto_clean(void);

#endif
