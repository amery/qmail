#ifndef HEADERBODY_H
#define HEADERBODY_H

#include "stralloc.h"
#include "substdio.h"

extern int headerbody(substdio *,
    void (*)(stralloc *), void (*)(void), void (*)(stralloc *));

#endif
