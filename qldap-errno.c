/*
 * Copyright (c) 2000-2004 Claudio Jeker,
 *      Internet Business Solutions AG, CH-8005 Zürich, Switzerland
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Internet Business
 *      Solutions AG and its contributors.
 * 4. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include "qldap-errno.h"
#include "error.h"

/* XXX TODO needs to be removed */
int qldap_errno;

const char *qldap_err_str(int enbr)
/* returns a string that corresponds to the qldap_errno */
{
	switch (enbr) {
	case OK:
		return "successful";
	case ERRNO:
		return error_str(errno);
	case FAILED:
		return "unspecified error";
	case PANIC:
		return "PANIC! Fatal error";

	case NOSUCH:
		return "no such object";
	case TOOMANY:
		return "too many objects";
	case TIMEOUT:
		return "operation timed out";

	case BADVAL:
		return "bad value";
	case ILLVAL:
		return "illegal value";
	case NEEDED:
		return "needed value is missing";

	case BADPASS:
		return "authorization failed, wrong password";
	case FORWARD:
		return "session needs to be forwarded";

	case BADCLUSTER:
		return "misconfigured cluster";
	case ACC_DISABLED:
		return "account disabled";
	case AUTH_EXEC:
		return "unable to start subprogram";
	case AUTH_CONF:
		return "configuration error";
	case AUTH_TYPE:
		return "unsupported authentication mode";

	case MAILDIR_NONEXIST:
		return "maildir/homedir does not exist";
	case MAILDIR_UNCONF:
		return "no dirmaker script configured";
	case MAILDIR_CORRUPT:
		return "maildir seems to be corrupted";
	case MAILDIR_CRASHED:
		return "dirmaker script crashed";
	case MAILDIR_FAILED:
		return "automatic maildir/homedir creation failed";
	case MAILDIR_HARD:
		return "hard error in maildir/homedir creation";
		
	case LDAP_BIND_UNREACH:
		return "ldap server down or unreachable";
	case LDAP_BIND_AUTH:
		return "wrong bind password for ldap server";
	default:
		return "unknown error occured";
	}
}

