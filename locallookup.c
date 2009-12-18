/*
 * Copyright (c) 2003-2004 Claudio Jeker,
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

/*
 * Based on D. J. Bernsteins checkpassword program.
 */

#include <sys/types.h>
#include <unistd.h>
#include "error.h"
#include "getln.h"
#include "localdelivery.h"
#include "open.h"
#include "passwd.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "substdio.h"

#include "checkpassword.h"
#include "locallookup.h"

/* Edit the first lines in the Makefile to enable local passwd lookups 
 * and debug options.
 * To use shadow passwords under Solaris, uncomment the 'SHADOWOPTS' line 
 * in the Makefile.
 * To use shadow passwords under Linux, uncomment the 'SHADOWOPTS' line and
 * the 'SHADOWLIBS=-lshadow' line in the Makefile.
 */
#include <pwd.h>
#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef AIX
#include <userpw.h>
#endif

int
check_passwd(stralloc *login, stralloc *authdata,
    struct credentials *c, int fast)
{
	int ret;
	struct passwd *pw;
#ifdef PW_SHADOW
	struct spwd *spw;
#endif
#ifdef AIX
	struct userpw *spw;
#endif

	if (localdelivery() == 0) return NOSUCH;

	pw = getpwnam(login->s);
	if (!pw) {
		/* XXX: unfortunately getpwnam() hides temporary errors */
		logit(32, "check_passwd: user %s not found in passwd db\n",
		    login->s);
		return NOSUCH;
	}
	logit(32, "check_passwd: user %s found in passwd db\n",
	    login->s);
	if (!fast) {
		c->gid = pw->pw_gid;
		c->uid = pw->pw_uid;
		/*
		 * Here we don't check the home and maildir path, if a user
		 * has a faked passwd entry, then you have a bigger problem
		 * on your system than just a guy how can read the mail of
		 * other users/customers.
		 */
		if (!stralloc_copys(&c->home, pw->pw_dir))
			return ERRNO;
		if (!stralloc_0(&c->home))
			return ERRNO;
	
		ret = get_local_maildir(&c->home, &c->maildir);
		if (ret != 0)
			return ret;
		logit(32, "get_local_maildir: maildir=%s\n", c->maildir.s);
	}

#ifdef PW_SHADOW
	spw = getspnam(login->s);
	if (!spw)
		/* XXX: again, temp hidden */
		return FAILED;
	ret = cmp_passwd((unsigned char*) authdata->s, spw->sp_pwdp);
#else /* no PW_SHADOW */
#ifdef AIX
	spw = getuserpw(login->s);
	if (!spw)
		/* XXX: and again */
		return FAILED;
	ret = cmp_passwd((unsigned char*) authdata->s, spw->upw_passwd);
#else /* no AIX */
	ret = cmp_passwd((unsigned char*) authdata->s, pw->pw_passwd);
#endif /* END AIX */
#endif /* END PW_SHADOW */
	logit(32, "check_pw: password compare was %s\n", 
	    ret==OK?"successful":"not successful");
	return ret;
}


int
get_local_maildir(stralloc *home, stralloc *maildir)
{
	substdio	ss;
	char		buf[512];
	int		dirfd, fd, match, save;
	
	dirfd = open_read(".");
	if (dirfd == -1)
		return ERRNO;
	if (chdir(home->s) == -1)
		return ERRNO;

	if ((fd = open_read(".qmail")) == -1) {
		if (errno == error_noent) return 0;
		return ERRNO;
	}

	substdio_fdbuf(&ss, subread, fd, buf, sizeof(buf));
	while (1) {
		if (getln(&ss, maildir, &match, '\n') != 0) goto tryclose;
		if (!match && !maildir->len) {
			if (!stralloc_copyb(maildir, "", 1)) goto tryclose;
			break;
		}
		if ((maildir->s[0] == '.' || maildir->s[0] == '/') && 
			  maildir->s[maildir->len-2] == '/') {
			maildir->s[maildir->len-1] = '\0';
			break;
		}
	}
	if (fchdir(dirfd) == -1)
		return ERRNO;
	close(dirfd);
	close(fd);
	return 0;

tryclose:
	save = errno; /* preserve errno */
	if (fchdir(dirfd) == -1)
		return ERRNO;
	close(dirfd);
	close(fd);
	errno = save;
	return ERRNO;
}

