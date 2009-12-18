#ifndef ENV_H
#define ENV_H

extern int env_isinit;

extern int env_init(void);
extern int env_put(const char *);
extern int env_put2(const char *, const char *);
extern int env_unset(const char *);
extern /*@null@*/char *env_get(const char *);
extern char *env_pick(void);
extern void env_clear(void);
extern const char *env_findeq(const char *);

extern char **environ;

#endif
