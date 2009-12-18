#include <signal.h>
#include "sig.h"

void sig_hangupblock(void) { sig_block(SIGHUP); }
void sig_hangupunblock(void) { sig_unblock(SIGHUP); }
void sig_hangupcatch(f) void (*f)(); { sig_catch(SIGHUP,f); }
void sig_hangupdefault(void) { sig_catch(SIGHUP,SIG_DFL); }
