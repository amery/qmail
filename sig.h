#ifndef SIG_H
#define SIG_H

extern void sig_catch(int, void (*)());
extern void sig_block(int);
extern void sig_unblock(int);
extern void sig_blocknone(void);
extern void sig_pause(void);

extern void sig_dfl();

extern void sig_miscignore(void);
extern void sig_bugcatch(void (*)());

extern void sig_pipeignore(void);
extern void sig_pipedefault(void);

/* XXX not available in qmail-1.03
extern void sig_contblock();
extern void sig_contunblock();
extern void sig_contcatch();
extern void sig_contdefault();
*/

extern void sig_termblock(void);
extern void sig_termunblock(void);
extern void sig_termcatch(void (*)());
extern void sig_termdefault(void);

extern void sig_alarmblock(void);
extern void sig_alarmunblock(void);
extern void sig_alarmcatch(void (*)());
extern void sig_alarmdefault(void);

extern void sig_childblock(void);
extern void sig_childunblock(void);
extern void sig_childcatch(void (*)());
extern void sig_childdefault(void);

extern void sig_hangupblock(void);
extern void sig_hangupunblock(void);
extern void sig_hangupcatch(void (*)());
extern void sig_hangupdefault(void);

#endif
