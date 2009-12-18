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
#ifndef __AUTH_MOD_H__
#define __AUTH_MOD_H__

#include "stralloc.h"

extern const unsigned int auth_port;

/* 
 * auth_init must return the 0-terminated strings login and authdata.
 * possible arguments should be parsed and the argument for auth_success
 * need to be stored if later needed.
 */
void auth_init(int, char **, stralloc *, stralloc *);

/*
 * Checks if it was a hard fail (bad password) or just a soft error 
 * (user not found). May start an other auth_module. MAY NOT return.
 */
void auth_fail(const char *, int);

/* starts the next auth_module, or what ever (argv ... ) */
void auth_success(const char *);

/*
 * Error handler, for this module, MAY NOT return.
 * auth_error MAY be called befor auth_init so it is not possible to
 * use the argument passed to auth_init in this function.
 */
void auth_error(int);

/*
 * for connection forwarding, makes the login part and returns after 
 * sending the latest command immidiatly
 */
void auth_forward(int fd, char *login, char *passwd);

/*
 * returns the default maildir if it is not defined, this is normally
 * the last argument of the execution chain.
 */
char *auth_aliasempty(void);

#endif
