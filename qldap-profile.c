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
#include "taia.h"
#include "qldap-profile.h"
#include "qldap-debug.h"

struct profile_t {
	struct taia start;
	char *function;
};
	
static struct profile_t profile_list[PROFILES_MAX];

void start_timing(unsigned int profile, char *function)
{
	if (profile >= PROFILES_MAX) {
		debug(0x400, "Max Number of profiles exceeded\n");
		return;
	}
	
	taia_now(&(profile_list[profile].start));

}

void stop_timing(unsigned int profile) 
{
	struct taia stop;
	struct taia diff;
	char nano[TAIA_FMTFRAC];
	unsigned long sec;
	
	if (profile >= PROFILES_MAX) {
		debug(0x400, "Max Number of profiles exceeded\n");
		return;
	}

	taia_now(&stop);

	taia_sub(&diff, &stop, &profile_list[profile].start);
	nano[taia_fmtfrac(nano, &diff)] = 0; /* terminate to be sure */
	nano[7] = 0; /* only the first 6-7 figures are != 0, (nano seconds) */
	sec=(unsigned long) ((unsigned long long) diff.sec.x);
	debug(0x400, "%s took %u.%s Sec\n", profile_list[profile].function, sec, nano);

}

