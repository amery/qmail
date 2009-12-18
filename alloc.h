#ifndef ALLOC_H
#define ALLOC_H

extern /*@null@*//*@out@*/void *alloc(unsigned int);
extern void alloc_free(void *);
extern int alloc_re(char **, unsigned int, unsigned int);

#endif
