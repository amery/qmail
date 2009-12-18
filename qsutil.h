#ifndef QSUTIL_H
#define QSUTIL_H

extern void log1(const char *);
extern void log2(const char *, const char *);
extern void log3(const char *, const char *, const char *);
extern void logsa(stralloc *);
extern void nomem(void);
extern void pausedir(const char *);
extern void logsafe(const char *);

#endif
