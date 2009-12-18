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
#ifndef __QLDAP_ERRNO_H__
#define __QLDAP_ERRNO_H__

/* XXX TODO cleanup */

extern int qldap_errno;

/* generic errors */
#define OK			0	/* all OK */
#define ERRNO			1	/* check errno for more info */
#define FAILED			2	/* generic failed message */
#define PANIC			3	/* fatal error happend */

#define NOSUCH			4	/* no such object */
#define TOOMANY			5	/* too many objects */
#define TIMEOUT			6	/* operation timed out */

#define BADVAL			7	/* bad value */
#define ILLVAL			8	/* illegal value (check failed) */
#define NEEDED			9	/* needed value is missing */

#define BADPASS			10	/* auth failed wrong password */
#define FORWARD			11	/* session needs to be forwarded */

/* auth_mod and checkpassword specific errors */
#define BADCLUSTER		20	/* bad settings for clustering */
#define ACC_DISABLED		21	/* account disabled */
#define AUTH_EXEC		22	/* unable to start subprogram */
#define AUTH_CONF		23	/* configuration error */
#define AUTH_TYPE		24	/* unsuportet auth type */

/* maildirmake specific errors */
#define MAILDIR_NONEXIST	25	/* maildir/homedir does not exist */
#define MAILDIR_UNCONF		26	/* no dirmaker script configured */
#define MAILDIR_CORRUPT		27	/* maildir seems to be corrupted */
#define MAILDIR_CRASHED		28	/* dirmaker script crashed */
#define MAILDIR_FAILED		29	/* automatic maildir creation failed */
#define MAILDIR_HARD		30	/* hard error in maildir creation */

/* LDAP specific errnos */
#define LDAP_BIND_UNREACH	31	/* ldap server down or unreachable */
#define LDAP_BIND_AUTH		32	/* wrong bind password */

const char *qldap_err_str(int enbr);
/* returns a string that corresponds to the qldap_errno */

#endif
