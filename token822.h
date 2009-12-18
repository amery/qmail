#ifndef TOKEN822_H
#define TOKEN822_H

struct token822
 {
  int type;
  const char *s;
  unsigned int slen;
 }
;

#include "gen_alloc.h"
#include "stralloc.h"

GEN_ALLOC_typedef(token822_alloc,struct token822,t,len,a)

extern int token822_parse(token822_alloc *, stralloc *, stralloc *);
extern int token822_addrlist(token822_alloc *, token822_alloc *,
    token822_alloc *, int (*)());
extern int token822_unquote(stralloc *, token822_alloc *);
extern int token822_unparse(stralloc *, token822_alloc *, unsigned int);
/* XXX not available in qmail-1.03
extern void token822_free();
*/
extern void token822_reverse(token822_alloc *);
extern int token822_ready(token822_alloc *, unsigned int);
extern int token822_readyplus(token822_alloc *, unsigned int);
extern int token822_append(token822_alloc *, struct token822 *);

#define TOKEN822_ATOM 1
#define TOKEN822_QUOTE 2
#define TOKEN822_LITERAL 3
#define TOKEN822_COMMENT 4
#define TOKEN822_LEFT 5
#define TOKEN822_RIGHT 6
#define TOKEN822_AT 7
#define TOKEN822_COMMA 8
#define TOKEN822_SEMI 9
#define TOKEN822_COLON 10
#define TOKEN822_DOT 11

#endif
