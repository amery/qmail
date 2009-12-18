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
#include "qmail-ldap.h"
#include "check.h"
#include "str.h"

extern unsigned char testvektor[128];

/* XXX this is not a security checker, it just looks that no special chars 
 * XXX are in the string this is because the ldap server could send some 
 * XXX faked datas */
int sanitycheckb(char *s, unsigned int len, unsigned char mask)
{
	unsigned char *tv;
	unsigned int x;

	tv = testvektor;
	
	x = (unsigned int)*s++; if (!len--) return 1;
	/* is this char allowed as first char (normaly '-' is not) */
	if (x > 0x7F || !(tv[x] & mask) || tv[x] & NOT_FIRST) return 0;

	for (;;) {
		x = (unsigned int)*s++; if (!len--) return 1;
		if (x > 0x7F || !(tv[x] & mask)) return 0;
		x = (unsigned int)*s++; if (!len--) return 1;
		if (x > 0x7F || !(tv[x] & mask)) return 0;
		x = (unsigned int)*s++; if (!len--) return 1;
		if (x > 0x7F || !(tv[x] & mask)) return 0;
		x = (unsigned int)*s++; if (!len--) return 1;
		if (x > 0x7F || !(tv[x] & mask)) return 0;
	}
	return 0; /* paranoia */
}

/* XXX this is not a security checker, it just looks that no special chars 
 * XXX are in the string this is because the ldap server could send some 
 * XXX faked datas */
int sanitypathcheckb(char *s, unsigned int len, unsigned char mask)
/* works like sanitycheckb but also looks that there is no '..' in the
 * string. This should be used for maildirpaths */
{
	unsigned char *tv;
	unsigned int x;
	enum { NODOT, FIRST, SLASH, ONEDOT, TWODOT } state = FIRST;

	tv = testvektor;
	
	while (len--) {
		x = (unsigned int)*s++;
		if (x > 0x7F || !(tv[x] & mask)) return 0;
		if (state == FIRST && tv[x] & NOT_FIRST) return 0;
		switch (x) {
		case '.':
			switch (state) {
			case ONEDOT:
				state = TWODOT;
				break;
			case NODOT:
				break;
			default:
				state = ONEDOT;
			}
			break;
		case '/':
			if (state == TWODOT)
				return 0;
			state = SLASH;
			break;
		default:
			state = NODOT;
			break;
		}
	}
	return 1;
}

int sanitychecks(register char *s, register unsigned char mask) 
{
	return sanitycheckb(s, str_len(s), mask);
}

int sanitypathchecks(register char *s, register unsigned char mask) 
{
	return sanitypathcheckb(s, str_len(s), mask);
}

/************************************************************
You can allow or deny chars by adding:
  DENY_ALL:   always deny this char
  ALLOW_ALL:  always allow this char
  ALLOW_USER: allow this char for username checks (chck_user)
  DENY_USER:  deny this char for username checks (chck_user)
  ALLOW_PATH: allow this char for path checks (chck_path)
  DENY_PATH:  deny this char for path checks (chck_path)
  ALLOW_PROG: allow this char for program checks (chck_prog)
  DENY_PROG:  deny this char for program checks (chck_prog)
  NOT_FIRST:  deny this char at the beginning of a string
  SPACE:      alias to ALLOW_PROG
  PARANOIA:   deny most shell special chars like '|' or '*' for program checks
              can be turned on or of in qmail-ldap.h
  Example:
   * 7  \007 ^G * DENY_ALL,               * deny control chars *
   * 45 '-'     * ALLOW_ALL|NOT_FIRST,    * allowed but not first *
   * 47 '/'     * ALLOW_ALL&DENY_USER,    * allowed only for path and prog *
   * 58 ':'     * ALLOW_PROG|ALLOW_PATH,  * like before *
 
  As you can see ALLOWs have to be ORed together whereas DENYs have to be ANDed
  NOT_FIRST has to be ORed and PARANOIA has to be ANDed.

************************************************************/

unsigned char testvektor[128] = { 
#define SPACE			ALLOW_PROG
#if RESTRICT_PROG == 1
# define PARANOIA		DENY_PROG
#else
# define PARANOIA		0xFF
#endif
	/* nr	char		*/
	/********************/
	/* 0	\000	^@	*/	DENY_ALL,
	/* 1	\001	^A	*/	DENY_ALL,
	/* 2	\002	^B	*/	DENY_ALL,
	/* 3	\003	^C	*/	DENY_ALL,
	/* 4	\004	^D	*/	DENY_ALL,
	/* 5	\005	^E	*/	DENY_ALL,
	/* 6	\006	^F	*/	DENY_ALL,
	/* 7	\007	^G	*/	DENY_ALL,
	/* 8	\010	^F	*/	DENY_ALL,
	/* 9	\011	\t	*/	SPACE,
	/* 10	\012	\n	*/	SPACE,
	/* 11	\013	^K	*/	DENY_ALL,
	/* 12	\014	^L	*/	DENY_ALL,
	/* 13	\015	^M	*/	DENY_ALL,
	/* 14	\016	^N	*/	DENY_ALL,
	/* 15	\017	^O	*/	DENY_ALL,
	/* 16	\020	^P	*/	DENY_ALL,
	/* 17	\021	^Q	*/	DENY_ALL,
	/* 18	\022	^R	*/	DENY_ALL,
	/* 19	\023	^S	*/	DENY_ALL,
	/* 20	\024	^T	*/	DENY_ALL,
	/* 21	\025	^U	*/	DENY_ALL,
	/* 22	\026	^V	*/	DENY_ALL,
	/* 23	\027	^W	*/	DENY_ALL,
	/* 24	\030	^X	*/	DENY_ALL,
	/* 25	\031	^Y	*/	DENY_ALL,
	/* 26	\032	^Z	*/	DENY_ALL,
	/* 27	\033	ESC	*/	DENY_ALL,
	/* 28	\034	^\	*/	DENY_ALL,
	/* 29	\035	^]	*/	DENY_ALL,
	/* 30	\036	^^	*/	DENY_ALL,
	/* 31	\037	^_	*/	DENY_ALL,
	/* 32	' '			*/	SPACE,
	/* 33	'!'			*/	ALLOW_PROG&PARANOIA,
	/* 34	'"'			*/	ALLOW_PROG,
	/* 35	'#'			*/	ALLOW_ALL,
	/* 36	'$'			*/	ALLOW_PROG&PARANOIA,
	/* 37	'%'			*/	ALLOW_PROG&PARANOIA,
	/* 38	'&'			*/	ALLOW_PROG&PARANOIA,
	/* 39	'''			*/	ALLOW_PROG,
	/* 40	'('			*/	ALLOW_PROG&PARANOIA,
	/* 41	')'			*/	ALLOW_PROG&PARANOIA,
	/* 42	'*'			*/	ALLOW_PROG&PARANOIA,
	/* 43	'+'			*/	ALLOW_PROG,
	/* 44	','			*/	ALLOW_PROG,
	/* 45	'-'			*/	ALLOW_ALL|NOT_FIRST, /*XXX*/
	/* 46	'.'			*/	ALLOW_ALL,
	/* 47	'/'			*/	ALLOW_ALL&DENY_USER,
	/* 48	'0'			*/	ALLOW_ALL,
	/* 49	'1'			*/	ALLOW_ALL,
	/* 50	'2'			*/	ALLOW_ALL,
	/* 51	'3'			*/	ALLOW_ALL,
	/* 52	'4'			*/	ALLOW_ALL,
	/* 53	'5'			*/	ALLOW_ALL,
	/* 54	'6'			*/	ALLOW_ALL,
	/* 55	'7'			*/	ALLOW_ALL,
	/* 56	'8'			*/	ALLOW_ALL,
	/* 57	'9'			*/	ALLOW_ALL,
	/* 58	':'			*/	ALLOW_PROG|ALLOW_PATH,
	/* 59	';'			*/	ALLOW_PROG&PARANOIA,
	/* 60	'<'			*/	ALLOW_PROG&PARANOIA,
	/* 61	'='			*/	ALLOW_PROG|ALLOW_PATH,
	/* 62	'>'			*/	ALLOW_PROG&PARANOIA,
	/* 63	'?'			*/	ALLOW_PROG&PARANOIA,
	/* 64	'@'			*/	ALLOW_USER|ALLOW_PATH|ALLOW_PROG, /*XXX*/
	/* 65	'A'			*/	ALLOW_ALL,
	/* 66	'B'			*/	ALLOW_ALL,
	/* 67	'C'			*/	ALLOW_ALL,
	/* 68	'D'			*/	ALLOW_ALL,
	/* 69	'E'			*/	ALLOW_ALL,
	/* 70	'F'			*/	ALLOW_ALL,
	/* 71	'G'			*/	ALLOW_ALL,
	/* 72	'H'			*/	ALLOW_ALL,
	/* 73	'I'			*/	ALLOW_ALL,
	/* 74	'J'			*/	ALLOW_ALL,
	/* 75	'K'			*/	ALLOW_ALL,
	/* 76	'L'			*/	ALLOW_ALL,
	/* 77	'M'			*/	ALLOW_ALL,
	/* 78	'N'			*/	ALLOW_ALL,
	/* 79	'O'			*/	ALLOW_ALL,
	/* 80	'P'			*/	ALLOW_ALL,
	/* 81	'Q'			*/	ALLOW_ALL,
	/* 82	'R'			*/	ALLOW_ALL,
	/* 83	'S'			*/	ALLOW_ALL,
	/* 84	'T'			*/	ALLOW_ALL,
	/* 85	'U'			*/	ALLOW_ALL,
	/* 86	'V'			*/	ALLOW_ALL,
	/* 87	'W'			*/	ALLOW_ALL,
	/* 88	'X'			*/	ALLOW_ALL,
	/* 89	'Y'			*/	ALLOW_ALL,
	/* 90	'Z'			*/	ALLOW_ALL,
	/* 91	'['			*/	ALLOW_PROG&PARANOIA,
	/* 92	'\\'			*/	ALLOW_PROG,
	/* 93	']'			*/	ALLOW_PROG&PARANOIA,
	/* 94	'^'			*/	ALLOW_PROG&PARANOIA,
	/* 95	'_'			*/	ALLOW_ALL,
	/* 96	'`'			*/	ALLOW_PROG&PARANOIA,
	/* 97	'a'			*/	ALLOW_ALL,
	/* 98	'b'			*/	ALLOW_ALL,
	/* 99	'c'			*/	ALLOW_ALL,
	/* 100	'd'			*/	ALLOW_ALL,
	/* 101	'e'			*/	ALLOW_ALL,
	/* 102	'f'			*/	ALLOW_ALL,
	/* 103	'g'			*/	ALLOW_ALL,
	/* 104	'h'			*/	ALLOW_ALL,
	/* 105	'i'			*/	ALLOW_ALL,
	/* 106	'j'			*/	ALLOW_ALL,
	/* 107	'k'			*/	ALLOW_ALL,
	/* 108	'l'			*/	ALLOW_ALL,
	/* 109	'm'			*/	ALLOW_ALL,
	/* 110	'n'			*/	ALLOW_ALL,
	/* 111	'o'			*/	ALLOW_ALL,
	/* 112	'p'			*/	ALLOW_ALL,
	/* 113	'q'			*/	ALLOW_ALL,
	/* 114	'r'			*/	ALLOW_ALL,
	/* 115	's'			*/	ALLOW_ALL,
	/* 116	't'			*/	ALLOW_ALL,
	/* 117	'u'			*/	ALLOW_ALL,
	/* 118	'v'			*/	ALLOW_ALL,
	/* 119	'w'			*/	ALLOW_ALL,
	/* 120	'x'			*/	ALLOW_ALL,
	/* 121	'y'			*/	ALLOW_ALL,
	/* 122	'z'			*/	ALLOW_ALL,
	/* 123	'{'			*/	ALLOW_PROG&PARANOIA,
	/* 124	'|'			*/	ALLOW_PROG&PARANOIA,
	/* 125	'}'			*/	ALLOW_PROG&PARANOIA,
	/* 126	'~'			*/	ALLOW_PROG&PARANOIA,
	/* 127	^?			*/	DENY_ALL
};

