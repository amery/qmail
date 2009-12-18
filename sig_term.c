#include <signal.h>
#include "sig.h"

void sig_termblock(void) { sig_block(SIGTERM); }
void sig_termunblock(void) { sig_unblock(SIGTERM); }
void sig_termcatch(f) void (*f)(); { sig_catch(SIGTERM,f); }
void sig_termdefault(void) { sig_catch(SIGTERM,SIG_DFL); }
