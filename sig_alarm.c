#include <signal.h>
#include "sig.h"

void sig_alarmblock(void) { sig_block(SIGALRM); }
void sig_alarmunblock(void) { sig_unblock(SIGALRM); }
void sig_alarmcatch(f) void (*f)(); { sig_catch(SIGALRM,f); }
void sig_alarmdefault(void) { sig_catch(SIGALRM,SIG_DFL); }
