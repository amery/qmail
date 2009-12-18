/*
 * Copyright (c) 1998-2004 Andre Oppermann, Claudio Jeker,
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
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "base64.h"
#include "case.h"
#include "error.h"
#include "passwd.h"
#include "qldap-errno.h"
#include "readwrite.h"
#include "sgetopt.h"
#include "stralloc.h"


#define RANDDEV "/dev/urandom"

const char *mode[] = {
	"{CRYPT}",
       	"{MD4}",
       	"{MD5}",
       	"{NS-MTA-MD5}",
       	"{SMD5}",
       	"{SHA}",
       	"{SSHA}",
       	"{RMD160}",
       	0
};

const char *mode2[] = {
	"crypt",
       	"md4",
       	"md5",
       	"ns-mta-md5",
       	"smd5",
       	"sha",
       	"ssha",
       	"rmd160",
       	0
};

stralloc pw = {0};
stralloc salt = {0};

void
usage(void)
{
	fprintf(stderr,
	    "usage:\tdigest [ -c ] [ -b | -5 | -C | -f cryptformat ] [ -s base64Salt ]\n\t[ -S hexSalt ] [ -t type ] passwd\n"
	    "\tdigest -v password hashedPassword\n");
	exit(1);
}

void
getsalt(stralloc *b, int blen)
{
	char buf[64];
	int l, fd;
	
	fd = open(RANDDEV, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "digest: open %s failed: %s.\n",
		    RANDDEV, error_str(errno));
		exit(1);
	}
	l = read(fd, buf, sizeof(buf));
	if (l == -1) {
		fprintf(stderr, "digest: read failed: %s.\n",
		    error_str(errno));
		exit(1);
	}
	if (l < blen) {
		fprintf(stderr, "digest: not enough random data read.\n");
		exit(1);
	}
	if (!stralloc_copyb(b, buf, blen)) {
		fprintf(stderr, "digest: stralloc_copyb failed: %s.\n",
		    error_str(errno));
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int	i, opt, m, type = -1;
	char	*clear, *encrypted;
	const char *cformat;
	
	clear = (char *)0;
	encrypted = (char *)0;
	m = 0;
	cformat = "XX";
	while ((opt = getopt(argc, argv, "5bcf:s:S:t:v")) != opteof)
		switch (opt) {
		case '5':
			/* md5 format */
			cformat = "$1$XXXXXXXX$";
			break;
		case 'b':
			/* blowfish format */
			cformat = "$2a$07$XXXXXXXXXXXXXXXXXXXXXXXX";
			break;
		case 'C':
			/* good (acctually bad) old crypt */
			cformat = "XX";
			break;
		case 'c':
			m = 0;
			break;
		case 'f':
			cformat = optarg;
			break;
		case 's':
			if (b64_ptons(optarg, &salt) == -1) {
				fprintf(stderr, "digest: bad base64 string.\n");
				usage();
			}
			break;
		case 'S':
			if (hex_ptons(optarg, &salt) == -1) {
				fprintf(stderr, "digest: bad hex string.\n");
				usage();
			}
			break;
		case 't':
			for (i = 0; mode2[i] != 0; i++)
				if (!case_diffs(mode2[i], optarg))
					break;
			if (mode2[i]) {
				type = i;
				break;
			}
			fprintf(stderr,
			    "digest: bad digest type, use one of:\n");
			for (i = 0; mode2[i] != 0; i++)
				fprintf(stderr, "\t%s\n", mode2[i]);
			exit(1);
		case 'v':
			m = 1;
			break;
		default:
			
			usage();
		}

	argc -= optind;
	argv += optind;
	if (m == 0) {
		if (argc != 1) usage();
		clear = argv[0];
		if (salt.s == 0)
			getsalt(&salt, 18); /* actually 128bit salt but add
					     * a bit for base64 errors */
		feed_salt(salt.s, salt.len);
		feed_crypt(cformat);
		if (type != -1) {
			if (make_passwd(mode[type], clear, &pw) == OK) {
				stralloc_0(&pw);
				printf("%s%s\n", mode[type], pw.s);
			} else
				printf("%s failed.\n", mode2[type]);
		} else 
			for (i = 0; mode[i] != 0; i++) {
				if (make_passwd(mode[i], clear, &pw) == OK) {
					stralloc_0(&pw);
					printf("%s%s\n", mode[i], pw.s);
				} else
					printf("%s failed.\n", mode2[i]);
			}
	} else {
		if (argc != 2) usage();
		clear = argv[0];
		encrypted = argv[1];
		switch(cmp_passwd(clear, encrypted)) {
		case OK:
			printf("passwords are equal.\n");
			break;
		case BADPASS:
			printf("passwords are NOT equal.\n");
			break;
		case ERRNO:
			printf("digest: cmp_passwd: %s.\n", error_str(errno));
			exit(1);
		case ILLVAL:
			printf("digest: cmp_password: "
			    "illegal hashed password.\n");
			exit(1);
		default:
			printf("digest: cmp_password: failed.");
			exit(1);
		}
	}
	
	exit(0);
}

