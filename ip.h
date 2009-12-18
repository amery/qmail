#ifndef IP_H
#define IP_H

struct ip_address { unsigned char d[4]; } ;

extern unsigned int ip_fmt(char *, struct ip_address *);
#define IPFMT 19
extern unsigned int ip_scan(const char *, struct ip_address *);
extern unsigned int ip_scanbracket(const char *, struct ip_address *);

#endif
