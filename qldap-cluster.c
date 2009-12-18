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
#ifdef QLDAP_CLUSTER
#include "constmap.h"
#include "control.h"
#include "qldap-debug.h"
#include "str.h"
#include "stralloc.h"

#include "qldap-cluster.h"

static int		clusteron;
static stralloc		me = {0};
static stralloc		mh = {0};	/* buffer for constmap */
static struct constmap	mailhosts_map;


int
cluster_init(void)
{
	clusteron = 0;	/* default is off */
	
	if (control_readline(&me, "control/me") != 1)
		return -1;
	if (control_readint(&clusteron, "control/ldapcluster") == -1)
		return -1;
	logit(64, "init: control/ldapcluster: %i\n", clusteron);

	if (clusteron == 0)
		return 0;
	
	if (control_readfile(&mh,"control/ldapclusterhosts",0) == -1)
		return -1;
	logit(64, "init_ldap: control/ldapclusterhosts: read\n");
	if (!stralloc_cat(&mh, &me) || !stralloc_0(&mh))
		return -1;
	if (mailhosts_map.num != 0) constmap_free(&mailhosts_map);
	if (!constmap_init(&mailhosts_map, mh.s, mh.len,0))
		return -1;
	return 0;
}

int
cluster(char *mailhost)
/* returns 1 if mail/connection needs to be forwarded else 0 */
{
	if (clusteron == 0 || mailhost == (char *)0)
		return 0;
	if (constmap(&mailhosts_map, mailhost, str_len(mailhost)) == 0)
		return 1;
	else
		return 0;
}

stralloc *
cluster_me(void)
{
	return &me;
}

#endif
