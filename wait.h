#ifndef WAIT_H
#define WAIT_H

extern int wait_pid(int *, int);
extern int wait_nohang(int *);
/* XXX not available in qmail-1.03
extern int wait_stop();
extern int wait_stopnohang();
*/
#define wait_crashed(w) ((w) & 127)
#define wait_exitcode(w) ((w) >> 8)
#define wait_stopsig(w) ((w) >> 8)
#define wait_stopped(w) (((w) & 127) == 127)

#endif
