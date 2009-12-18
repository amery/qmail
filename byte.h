#ifndef BYTE_H
#define BYTE_H

extern unsigned int byte_chr(const char *, unsigned int, int);
extern unsigned int byte_rchr(const char *, unsigned int, int);
extern void byte_copy(void *, unsigned int, const void *);
extern void byte_copyr(void *, unsigned int, const void *);
extern int byte_diff(const void *, unsigned int, const void *);
extern void byte_zero(void *, unsigned int);
extern unsigned int byte_repl(char *, unsigned int, int, int);

#define byte_equal(s,n,t) (!byte_diff((s),(n),(t)))

#endif
