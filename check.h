/*
 * Copyright (c) 1998-2004 Claudio Jeker,
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
#ifndef _CHECK_H_
#define _CHECK_H_


#define DENY_ALL	0x00
#define ALLOW_USER	0x01
#define ALLOW_PATH	0x02
#define ALLOW_PROG	0x04
#define ALLOW_ALL	(ALLOW_USER | ALLOW_PATH | ALLOW_PROG)
#define DENY_USER	(unsigned char) ~ALLOW_USER
#define DENY_PATH	(unsigned char) ~ALLOW_PATH
#define DENY_PROG	(unsigned char) ~ALLOW_PROG
#define NOT_FIRST	0x80


extern int sanitycheckb(char *, unsigned int, unsigned char);
extern int sanitychecks(char *, unsigned char);

extern int sanitypathcheckb(char *, unsigned int , unsigned char);
extern int sanitypathchecks(char *, unsigned char);

#define check_userb(str, len)	sanitycheckb((str), (len), ALLOW_USER)
#define check_users(str)	sanitychecks((str), ALLOW_USER)

#define check_pathb(str, len)	sanitypathcheckb((str), (len), ALLOW_PATH)
#define check_paths(str)	sanitypathchecks((str), ALLOW_PATH)

#define check_progb(str, len)	sanitycheckb((str), (len), ALLOW_PROG)
#define check_progs(str)	sanitychecks((str), ALLOW_PROG)

#endif
