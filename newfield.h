#ifndef NEWFIELD_H
#define NEWFIELD_H

#include "datetime.h"
#include "stralloc.h"

extern stralloc newfield_date;
extern int newfield_datemake(datetime_sec);

extern stralloc newfield_msgid;
extern int newfield_msgidmake(const char *, int, datetime_sec);

#endif
