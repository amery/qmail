#include <signal.h>
#include "sig.h"

void sig_childblock(void) { sig_block(SIGCHLD); }
void sig_childunblock(void) { sig_unblock(SIGCHLD); }
void sig_childcatch(f) void (*f)(); { sig_catch(SIGCHLD,f); }
void sig_childdefault(void) { sig_catch(SIGCHLD,SIG_DFL); }
