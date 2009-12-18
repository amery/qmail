# Edit this few lines to configure your ldap stuff

# to enable some additional for qmail-ldap stuff put it on the LDAPFLAGS line
#
# -DALTQUEUE to use a diffrent qmail-queue programm on runtime
# -DBIGBROTHER to use the control/bigbrother file to forward all mails comming
#     from a specified account to another (swiss bigbrother law)
# -DBIGTODO to enable the big todo patch (this can be used together with 
#     EXTERNAL_TODO). Useful for servers with very many non-preprocessed mails
# -DBIND_8_COMPAT need if the compile fails building dns.c because of
#     undeclared defines. This is necessary on MacOS X 10.3.
# -DCLEARTEXTPASSWD to use cleartext passwords (bad idea on production systems)
# -DDASH_EXT to enable the dash_ext patch for extended mail addresses
# -DDATA_COMPRESS to use the smtp on the fly DATA compression 
# -DEXTERNAL_TODO to use the external high-performance todo processing (this
#     avoids the silly qmail syndrome with high injection rates)
# -DIGNOREVERISIGN to disallow dns wildchar matches on gtlds, thanks verisign.
# -DQLDAP_CLUSTER for enabling cluster support
# -DQMQP_COMPRESS to use the QMQP on the fly compression (for clusters)
# -DQUOTATRASH to include the Trash in the quota calculation (normaly it is not)
# -DSMTPEXECCHECK to enable smtp DOS/Windows executable detection
#LDAPFLAGS=-DQLDAP_CLUSTER -DEXTERNAL_TODO -DDASH_EXT -DDATA_COMPRESS -DQMQP_COMPRESS -DSMTPEXECCHECK

# Perhaps you have different ldap libraries, change them here
LDAPLIBS=-L/usr/local/lib -lldap -llber
# and change the location of the include files here
LDAPINCLUDES=-I/usr/local/include
# on Slowaris you need -lresolv and probably a LD_RUN_PATH added like this:
#LDAPLIBS=-L/opt/OpenLDAP/lib -lldap -llber -lresolv -R/opt/OpenLDAP/lib
# for example on my Linux box I use:
#LDAPLIBS=-L/opt/OpenLDAP/lib -lldap -llber
# if you need a special include-directory for ldap headers enable this
#LDAPINCLUDES=-I/opt/OpenLDAP/include

# ZLIB needed for -DDATA_COMPRESS and -DQMQP_COMPRESS
#ZLIB=-lz
# or you installed zlib in a different path you can use something like this
#ZLIB=-L/opt/zlib/lib -lz
#ZINCLUDES=-I/opt/zlib/include

# TLS (SMTP encryption) in qmail-smtpd and qmail-remote, see TLS.readme
# You need OpenSSL for this
# use -DTLS_REMOTE to enable tls support in qmail-remote
# use -DTLS_SMTPD to enable tls support in qmail-smtpd
# use -DTLSDEBUG to enable additional tls debug information in qmail-remote
#TLS=-DTLS_REMOTE -DTLS_SMTPD
# Path to OpenSSL includes
#TLSINCLUDES=-I/usr/local/include
# Path to OpenSSL libraries
#TLSLIBS=-L/usr/local/lib -lssl -lcrypto
# Path to OpenSSL binary
#OPENSSLBIN=/usr/local/bin/openssl
#OPENSSLBIN=openssl

# to make the Netscape download progress bar work with qmail-pop3d
# uncomment the next line (allready done)
MNW=-DMAKE_NETSCAPE_WORK 

# to enable the auto-maildir-make feature uncomment the next line
#MDIRMAKE=-DAUTOMAILDIRMAKE

# to enable the auto-homedir-make feature uncomment the next line
#HDIRMAKE=-DAUTOHOMEDIRMAKE

# on most systems we need this to make auth_pop and auth_imap
#SHADOWLIBS=-lcrypt
# OpenBSD and other Systems do not have libcrypt, so comment the line out
# if you get linking problems.
# To use shadow passwords under some Linux OS, uncomment the next two lines.
#SHADOWLIBS=-lcrypt -lshadow
#SHADOWOPTS=-DPW_SHADOW
# To use shadow passwords under Solaris, uncomment the SHADOWOPTS line.

# to enable the possibility to log and debug imap and pop uncoment the
# next line
#DEBUG=-DDEBUG
# WARNING: you need a NONE DEBUG auth_* to run with inetd

# for profiling ...
#INCTAI=../libtai-0.60
#LIBTAI=../libtai-0.60

# Just for me, make from time to time a backup
BACKUPPATH=/backup/qmail-backup/qmail-ldap.`date "+%Y%m%d-%H%M"`.tar
# STOP editing HERE !!!

# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: it ldap

ldap: qmail-quotawarn qmail-reply auth_pop auth_imap auth_smtp digest \
qmail-ldaplookup pbsadd pbscheck pbsdbd qmail-todo qmail-forward \
qmail-secretary qmail-group qmail-verify condwrite qmail-cdb \
qmail-imapd.run qmail-pbsdbd.run qmail-pop3d.run qmail-qmqpd.run \
qmail-smtpd.run qmail.run qmail-imapd-ssl.run qmail-pop3d-ssl.run \
Makefile.cdb-p

addresses.0: \
addresses.5
	nroff -man addresses.5 > addresses.0

alloc.a: \
makelib alloc.o alloc_re.o
	./makelib alloc.a alloc.o alloc_re.o

alloc.o: \
compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: \
compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

auth_imap: \
load auth_imap.o auth_mod.o checkpassword.o passwd.o digest_md4.o \
digest_md5.o digest_rmd160.o digest_sha1.o base64.o read-ctrl.o getopt.a \
control.o dirmaker.o mailmaker.o qldap.a localdelivery.o locallookup.o \
pbsexec.o constmap.o getln.a strerr.a substdio.a stralloc.a env.a wait.a \
dns.o ip.o ipalloc.o ipme.o alloc.a str.a case.a fs.a error.a timeoutconn.o \
timeoutread.o ndelay.a open.a sig.a prot.o auto_uids.o auto_qmail.o \
dns.lib socket.lib
	./load auth_imap auth_mod.o checkpassword.o passwd.o digest_md4.o \
	digest_md5.o digest_rmd160.o digest_sha1.o base64.o read-ctrl.o \
	getopt.a control.o dirmaker.o mailmaker.o qldap.a localdelivery.o \
	locallookup.o pbsexec.o constmap.o getln.a strerr.a substdio.a \
	stralloc.a env.a wait.a dns.o ip.o ipalloc.o ipme.o alloc.a str.a \
	case.a fs.a error.a timeoutconn.o timeoutread.o ndelay.a open.a \
	sig.a prot.o auto_uids.o auto_qmail.o $(LDAPLIBS) $(SHADOWLIBS) \
	`cat dns.lib` `cat socket.lib`

auth_imap.o: \
compile auth_imap.c alloc.h byte.h env.h error.h exit.h fmt.h pbsexec.h \
qldap-debug.h qldap-errno.h qmail-ldap.h readwrite.h scan.h sgetopt.h \
sig.h str.h stralloc.h substdio.h timeoutread.h auth_mod.h
	./compile $(LDAPFLAGS) $(DEBUG) auth_imap.c

auth_mod.o: \
compile auth_mod.c auth_mod.h checkpassword.h byte.h localdelivery.h \
locallookup.h output.h qldap.h qldap-debug.h qldap-errno.h stralloc.h \
read-ctrl.h dirmaker.h qldap-cluster.h select.h alloc.h
	./compile $(LDAPFLAGS) $(DEBUG) $(HDIRMAKE) $(MDIRMAKE) auth_mod.c

auth_pop: \
load auth_pop.o auth_mod.o checkpassword.o passwd.o digest_md4.o \
digest_md5.o digest_rmd160.o digest_sha1.o base64.o read-ctrl.o getopt.a \
control.o dirmaker.o mailmaker.o qldap.a localdelivery.o locallookup.o \
pbsexec.o constmap.o getln.a strerr.a substdio.a stralloc.a env.a wait.a \
dns.o ip.o ipalloc.o ipme.o alloc.a str.a case.a fs.a error.a timeoutconn.o \
timeoutread.o ndelay.a open.a prot.o auto_uids.o auto_qmail.o \
dns.lib socket.lib
	./load auth_pop auth_mod.o checkpassword.o passwd.o digest_md4.o \
	digest_md5.o digest_rmd160.o digest_sha1.o base64.o read-ctrl.o \
	getopt.a control.o qldap.a dirmaker.o mailmaker.o localdelivery.o \
	locallookup.o pbsexec.o constmap.o getln.a strerr.a substdio.a \
	stralloc.a env.a wait.a dns.o ip.o ipalloc.o ipme.o alloc.a str.a \
	case.a fs.a error.a timeoutconn.o timeoutread.o ndelay.a open.a \
	prot.o auto_uids.o auto_qmail.o $(LDAPLIBS) $(SHADOWLIBS) \
	`cat dns.lib` `cat socket.lib`

auth_pop.o: \
compile auth_pop.c byte.h env.h error.h exit.h pbsexec.h qldap-debug.h \
qldap-errno.h qmail-ldap.h readwrite.h sgetopt.h str.h stralloc.h substdio.h \
timeoutread.h auth_mod.h
	./compile $(LDAPFLAGS) $(DEBUG) auth_pop.c

auth_smtp: \
load auth_smtp.o checkpassword.o passwd.o digest_md4.o digest_md5.o \
digest_rmd160.o digest_sha1.o base64.o read-ctrl.o control.o qldap.a \
constmap.o getln.a strerr.a substdio.a stralloc.a env.a alloc.a str.a \
case.a fs.a error.a open.a prot.o auto_uids.o auto_qmail.o
	./load auth_smtp checkpassword.o passwd.o digest_md4.o \
	digest_md5.o digest_rmd160.o digest_sha1.o base64.o read-ctrl.o \
	control.o qldap.a constmap.o getln.a strerr.a substdio.a stralloc.a \
	env.a alloc.a str.a case.a fs.a error.a open.a prot.o auto_uids.o \
	auto_qmail.o $(LDAPLIBS) $(SHADOWLIBS)
	
auth_smtp.o: \
compile auth_smtp.c byte.h env.h error.h exit.h output.h qldap.h \
qldap-debug.h qldap-errno.h qmail-ldap.h read-ctrl.h str.h stralloc.h \
substdio.h checkpassword.h auth_mod.h
	./compile $(LDAPFLAGS) $(DEBUG) auth_smtp.c

auto-ccld.sh: \
conf-cc conf-ld warn-auto.sh
	( cat warn-auto.sh; \
	echo CC=\'`head -1 conf-cc`\'; \
	echo LD=\'`head -1 conf-ld`\' \
	) > auto-ccld.sh

auto-gid: \
load auto-gid.o substdio.a error.a str.a fs.a
	./load auto-gid substdio.a error.a str.a fs.a 

auto-gid.o: \
compile auto-gid.c subfd.h substdio.h substdio.h readwrite.h exit.h \
scan.h fmt.h
	./compile auto-gid.c

auto-int: \
load auto-int.o substdio.a error.a str.a fs.a
	./load auto-int substdio.a error.a str.a fs.a 

auto-int.o: \
compile auto-int.c substdio.h readwrite.h exit.h scan.h fmt.h
	./compile auto-int.c

auto-int8: \
load auto-int8.o substdio.a error.a str.a fs.a
	./load auto-int8 substdio.a error.a str.a fs.a 

auto-int8.o: \
compile auto-int8.c substdio.h readwrite.h exit.h scan.h fmt.h
	./compile auto-int8.c

auto-str: \
load auto-str.o substdio.a error.a str.a
	./load auto-str substdio.a error.a str.a 

auto-str.o: \
compile auto-str.c substdio.h readwrite.h exit.h
	./compile auto-str.c

auto-uid: \
load auto-uid.o substdio.a error.a str.a fs.a
	./load auto-uid substdio.a error.a str.a fs.a 

auto-uid.o: \
compile auto-uid.c subfd.h substdio.h substdio.h readwrite.h exit.h \
scan.h fmt.h
	./compile auto-uid.c

auto_break.c: \
auto-str conf-break
	./auto-str auto_break \
	"`head -1 conf-break`" > auto_break.c

auto_break.o: \
compile auto_break.c
	./compile auto_break.c

auto_patrn.c: \
auto-int8 conf-patrn
	./auto-int8 auto_patrn `head -1 conf-patrn` > auto_patrn.c

auto_patrn.o: \
compile auto_patrn.c
	./compile auto_patrn.c

auto_qmail.c: \
auto-str conf-qmail
	./auto-str auto_qmail `head -1 conf-qmail` > auto_qmail.c

auto_qmail.o: \
compile auto_qmail.c
	./compile auto_qmail.c

auto_spawn.c: \
auto-int conf-spawn
	./auto-int auto_spawn `head -1 conf-spawn` > auto_spawn.c

auto_spawn.o: \
compile auto_spawn.c
	./compile auto_spawn.c

auto_split.c: \
auto-int conf-split
	./auto-int auto_split `head -1 conf-split` > auto_split.c

auto_split.o: \
compile auto_split.c
	./compile auto_split.c

auto_uids.c: \
auto-uid auto-gid conf-users conf-groups
	( ./auto-uid auto_uida `head -1 conf-users` \
	&&./auto-uid auto_uidd `head -2 conf-users | tail -1` \
	&&./auto-uid auto_uidl `head -3 conf-users | tail -1` \
	&&./auto-uid auto_uido `head -4 conf-users | tail -1` \
	&&./auto-uid auto_uidp `head -5 conf-users | tail -1` \
	&&./auto-uid auto_uidq `head -6 conf-users | tail -1` \
	&&./auto-uid auto_uidr `head -7 conf-users | tail -1` \
	&&./auto-uid auto_uids `head -8 conf-users | tail -1` \
	&&./auto-gid auto_gidq `head -1 conf-groups` \
	&&./auto-gid auto_gidn `head -2 conf-groups | tail -1` \
	) > auto_uids.c.tmp && mv auto_uids.c.tmp auto_uids.c

auto_uids.o: \
compile auto_uids.c
	./compile auto_uids.c

auto_usera.c: \
auto-str conf-users
	./auto-str auto_usera `head -1 conf-users` > auto_usera.c

auto_usera.o: \
compile auto_usera.c
	./compile auto_usera.c

auto_userl.c: \
auto-str conf-users
	./auto-str auto_userl `head -3 conf-users | tail -1` > auto_userl.c

auto_userl.o: \
compile auto_userl.c
	./compile auto_userl.c

base64.o: \
compile base64.c base64.h str.h
	./compile $(LDAPFLAGS) base64.c

binm1: \
binm1.sh conf-qmail
	cat binm1.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm1
	chmod 755 binm1

binm1+df: \
binm1+df.sh conf-qmail
	cat binm1+df.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm1+df
	chmod 755 binm1+df

binm2: \
binm2.sh conf-qmail
	cat binm2.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm2
	chmod 755 binm2

binm2+df: \
binm2+df.sh conf-qmail
	cat binm2+df.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm2+df
	chmod 755 binm2+df

binm3: \
binm3.sh conf-qmail
	cat binm3.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm3
	chmod 755 binm3

binm3+df: \
binm3+df.sh conf-qmail
	cat binm3+df.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> binm3+df
	chmod 755 binm3+df

bouncesaying: \
load bouncesaying.o strerr.a error.a substdio.a str.a wait.a
	./load bouncesaying strerr.a error.a substdio.a str.a \
	wait.a 

bouncesaying.0: \
bouncesaying.1
	nroff -man bouncesaying.1 > bouncesaying.0

bouncesaying.o: \
compile bouncesaying.c fork.h strerr.h error.h wait.h sig.h exit.h
	./compile bouncesaying.c

byte_chr.o: \
compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: \
compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: \
compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: \
compile byte_diff.c byte.h
	./compile byte_diff.c

byte_rchr.o: \
compile byte_rchr.c byte.h
	./compile byte_rchr.c

byte_repl.o: \
compile byte_repl.c byte.h
	./compile byte_repl.c

byte_zero.o: \
compile byte_zero.c byte.h
	./compile byte_zero.c

case.a: \
makelib case_diffb.o case_diffs.o case_lowerb.o case_lowers.o \
case_startb.o case_starts.o
	./makelib case.a case_diffb.o case_diffs.o case_lowerb.o \
	case_lowers.o case_startb.o case_starts.o

case_diffb.o: \
compile case_diffb.c case.h
	./compile case_diffb.c

case_diffs.o: \
compile case_diffs.c case.h
	./compile case_diffs.c

case_lowerb.o: \
compile case_lowerb.c case.h
	./compile case_lowerb.c

case_lowers.o: \
compile case_lowers.c case.h
	./compile case_lowers.c

case_startb.o: \
compile case_startb.c case.h
	./compile case_startb.c

case_starts.o: \
compile case_starts.c case.h
	./compile case_starts.c

cdb.a: \
makelib cdb_hash.o cdb.o
	./makelib cdb.a cdb_hash.o cdb.o

cdb.o: \
compile cdb.c cdb.h byte.h  error.h seek.h uint32.h
	./compile cdb.c

cdb_hash.o: \
compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_make.o: \
compile cdb_make.c cdb.h readwrite.h seek.h error.h alloc.h uint32.h
	./compile cdb_make.c

cdbmake.a: \
makelib cdb_make.o cdb_hash.o
	./makelib cdbmake.a cdb_make.o cdb_hash.o

check: \
it man ldap
	./instcheck

check.o: \
compile check.c check.h str.h str_len.c
	./compile $(LDAPFLAGS) check.c

checkpassword.o: \
compile checkpassword.c auth_mod.h auto_uids.h byte.h check.h env.h \
error.h fmt.h localdelivery.h passwd.h pbsexec.h prot.h \
qldap.h qldap-debug.h qldap-errno.h qmail-ldap.h scan.h str.h stralloc.h \
dns.h ipalloc.h ipme.h ndelay.h qldap-cluster.h readwrite.h select.h \
timeoutconn.h dirmaker.h mailmaker.h
	./compile $(LDAPFLAGS) $(LDAPINCLUDES) $(DEBUG) checkpassword.c

chkshsgr: \
load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: \
compile chkshsgr.c exit.h
	./compile chkshsgr.c

chkspawn: \
load chkspawn.o substdio.a error.a str.a fs.a auto_spawn.o
	./load chkspawn substdio.a error.a str.a fs.a auto_spawn.o 

chkspawn.o: \
compile chkspawn.c substdio.h subfd.h substdio.h fmt.h select.h \
exit.h auto_spawn.h
	./compile chkspawn.c

clean: \
TARGETS
	rm -f `cat TARGETS`

coe.o: \
compile coe.c coe.h
	./compile coe.c

commands.o: \
compile commands.c commands.h substdio.h stralloc.h gen_alloc.h str.h \
case.h
	./compile commands.c

compile: \
make-compile warn-auto.sh systype
	( cat warn-auto.sh; ./make-compile "`cat systype`" ) > \
	compile
	chmod 755 compile

condredirect: \
load condredirect.o qmail.o strerr.a fd.a sig.a wait.a seek.a env.a \
substdio.a error.a str.a fs.a auto_qmail.o
	./load condredirect qmail.o strerr.a fd.a sig.a wait.a \
	seek.a env.a substdio.a error.a str.a fs.a auto_qmail.o 

condredirect.0: \
condredirect.1
	nroff -man condredirect.1 > condredirect.0

condredirect.o: \
compile condredirect.c sig.h readwrite.h exit.h env.h error.h fork.h \
wait.h seek.h qmail.h substdio.h strerr.h substdio.h fmt.h
	./compile condredirect.c

condwrite: \
load condwrite.o maildir++.o getln.a stralloc.a alloc.a env.a wait.a \
seek.a strerr.a substdio.a error.a gfrom.o str.a now.o fs.a mailmaker.o \
open.a sig.a lock.a auto_qmail.o
	./load condwrite maildir++.o getln.a stralloc.a alloc.a env.a \
	wait.a seek.a strerr.a substdio.a error.a gfrom.o str.a now.o \
	fs.a mailmaker.o open.a sig.a lock.a auto_qmail.o

condwrite.o: \
compile condwrite.c auto_qmail.h byte.h env.h error.h fmt.h getln.h gfrom.h \
lock.h maildir++.h now.h open.h qmail-ldap.h seek.h sig.h str.h stralloc.h \
strerr.h subfd.h substdio.h wait.h mailmaker.h qldap-errno.h
	./compile $(MDIRMAKE) condwrite.c

config: \
warn-auto.sh config.sh conf-qmail conf-break conf-split
	cat warn-auto.sh config.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> config
	chmod 755 config

config-fast: \
warn-auto.sh config-fast.sh conf-qmail conf-break conf-split
	cat warn-auto.sh config-fast.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> config-fast
	chmod 755 config-fast

constmap.o: \
compile constmap.c constmap.h alloc.h case.h
	./compile constmap.c

control.o: \
compile control.c readwrite.h open.h getln.h stralloc.h gen_alloc.h \
substdio.h error.h control.h alloc.h scan.h
	./compile control.c

date822fmt.o: \
compile date822fmt.c datetime.h fmt.h date822fmt.h
	./compile date822fmt.c

datemail: \
warn-auto.sh datemail.sh conf-qmail conf-break conf-split
	cat warn-auto.sh datemail.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> datemail
	chmod 755 datemail

datetime.a: \
makelib datetime.o datetime_un.o
	./makelib datetime.a datetime.o datetime_un.o

datetime.o: \
compile datetime.c datetime.h
	./compile datetime.c

datetime_un.o: \
compile datetime_un.c datetime.h
	./compile datetime_un.c

digest: \
load digest.o passwd.o digest_md4.o digest_md5.o digest_rmd160.o \
digest_sha1.o base64.o qldap-debug.o output.o getopt.a strerr.a \
substdio.a case.a env.a stralloc.a str.a fs.a alloc.a error.a
	./load digest passwd.o digest_md4.o digest_md5.o digest_rmd160.o \
	digest_sha1.o base64.o qldap-debug.o output.o getopt.a strerr.a \
	substdio.a case.a env.a stralloc.a str.a fs.a alloc.a error.a \
	$(SHADOWLIBS)

digest.o: \
compile digest.c base64.h error.h passwd.h qldap-errno.h \
sgetopt.h stralloc.h
	./compile $(LDAPFLAGS) digest.c

digest_md4.o: \
compile endian digest_md4.c byte.h digest_md4.h uint32.h
	./compile $(LDAPFLAGS) `./endian` digest_md4.c

digest_md5.o: \
compile endian digest_md5.c byte.h digest_md5.h uint32.h
	./compile $(LDAPFLAGS) `./endian` digest_md5.c

digest_rmd160.o: \
compile endian digest_rmd160.c byte.h digest_rmd160.h uint32.h
	./compile $(LDAPFLAGS) `./endian` digest_rmd160.c

digest_sha1.o: \
compile endian digest_sha1.c byte.h digest_sha1.h uint32.h
	./compile $(LDAPFLAGS) `./endian` digest_sha1.c

direntry.h: \
compile trydrent.c direntry.h1 direntry.h2
	( ./compile trydrent.c >/dev/null 2>&1 \
	&& cat direntry.h2 || cat direntry.h1 ) > direntry.h
	rm -f trydrent.o

dirmaker.o: \
compile dirmaker.c dirmaker.h control.h qldap-debug.h qldap-errno.h \
stralloc.h wait.h
	./compile $(HDIRMAKE) $(DEBUG) dirmaker.c

dns.lib: \
tryrsolv.c compile load socket.lib dns.o ipalloc.o ip.o stralloc.a \
alloc.a error.a fs.a str.a
	( ( ./compile tryrsolv.c && ./load tryrsolv dns.o \
	ipalloc.o ip.o stralloc.a alloc.a error.a fs.a str.a \
	-lresolv `cat socket.lib` ) >/dev/null 2>&1 \
	&& echo -lresolv || exit 0 ) > dns.lib
	rm -f tryrsolv.o tryrsolv

dns.o: \
compile dns.c ip.h ipalloc.h ip.h gen_alloc.h fmt.h alloc.h str.h \
stralloc.h gen_alloc.h dns.h case.h
	./compile $(LDAPFLAGS) dns.c

dnscname: \
load dnscname.o dns.o dnsdoe.o ip.o ipalloc.o stralloc.a alloc.a \
substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnscname dns.o dnsdoe.o ip.o ipalloc.o stralloc.a \
	alloc.a substdio.a error.a str.a fs.a  `cat dns.lib` `cat \
	socket.lib`

dnscname.o: \
compile dnscname.c substdio.h subfd.h substdio.h stralloc.h \
gen_alloc.h dns.h dnsdoe.h readwrite.h exit.h
	./compile dnscname.c

dnsdoe.o: \
compile dnsdoe.c substdio.h subfd.h substdio.h exit.h dns.h dnsdoe.h
	./compile dnsdoe.c

dnsfq: \
load dnsfq.o dns.o dnsdoe.o ip.o ipalloc.o stralloc.a alloc.a \
substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsfq dns.o dnsdoe.o ip.o ipalloc.o stralloc.a \
	alloc.a substdio.a error.a str.a fs.a  `cat dns.lib` `cat \
	socket.lib`

dnsfq.o: \
compile dnsfq.c substdio.h subfd.h substdio.h stralloc.h gen_alloc.h \
dns.h dnsdoe.h ip.h ipalloc.h ip.h gen_alloc.h exit.h
	./compile dnsfq.c

dnsip: \
load dnsip.o dns.o dnsdoe.o ip.o ipalloc.o stralloc.a alloc.a \
substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsip dns.o dnsdoe.o ip.o ipalloc.o stralloc.a \
	alloc.a substdio.a error.a str.a fs.a  `cat dns.lib` `cat \
	socket.lib`

dnsip.o: \
compile dnsip.c substdio.h subfd.h substdio.h stralloc.h gen_alloc.h \
dns.h dnsdoe.h ip.h ipalloc.h ip.h gen_alloc.h exit.h
	./compile dnsip.c

dnsmxip: \
load dnsmxip.o dns.o dnsdoe.o ip.o ipalloc.o now.o stralloc.a alloc.a \
substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsmxip dns.o dnsdoe.o ip.o ipalloc.o now.o \
	stralloc.a alloc.a substdio.a error.a str.a fs.a  `cat \
	dns.lib` `cat socket.lib`

dnsmxip.o: \
compile dnsmxip.c substdio.h subfd.h substdio.h stralloc.h \
gen_alloc.h fmt.h dns.h dnsdoe.h ip.h ipalloc.h ip.h gen_alloc.h \
now.h datetime.h exit.h
	./compile dnsmxip.c

dnsptr: \
load dnsptr.o dns.o dnsdoe.o ip.o ipalloc.o stralloc.a alloc.a \
substdio.a error.a str.a fs.a dns.lib socket.lib
	./load dnsptr dns.o dnsdoe.o ip.o ipalloc.o stralloc.a \
	alloc.a substdio.a error.a str.a fs.a  `cat dns.lib` `cat \
	socket.lib`

dnsptr.o: \
compile dnsptr.c substdio.h subfd.h substdio.h stralloc.h gen_alloc.h \
str.h scan.h dns.h dnsdoe.h ip.h exit.h
	./compile dnsptr.c

dot-qmail.0: \
dot-qmail.5
	nroff -man dot-qmail.5 > dot-qmail.0

dot-qmail.5: \
dot-qmail.9 conf-break conf-spawn
	cat dot-qmail.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> dot-qmail.5

elq: \
warn-auto.sh elq.sh conf-qmail conf-break conf-split
	cat warn-auto.sh elq.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> elq
	chmod 755 elq

endian: \
load endian.o
	./load endian

endian.o: \
compile endian.c
	./compile $(LDAPFLAGS) endian.c

env.a: \
makelib env.o envread.o
	./makelib env.a env.o envread.o

env.o: \
compile env.c str.h alloc.h env.h
	./compile env.c

envelopes.0: \
envelopes.5
	nroff -man envelopes.5 > envelopes.0

envread.o: \
compile envread.c env.h str.h
	./compile envread.c

error.a: \
makelib error.o error_str.o error_temp.o
	./makelib error.a error.o error_str.o error_temp.o

error.o: \
compile error.c error.h
	./compile error.c

error_str.o: \
compile error_str.c error.h
	./compile error_str.c

error_temp.o: \
compile error_temp.c error.h
	./compile error_temp.c

except: \
load except.o strerr.a error.a substdio.a str.a wait.a
	./load except strerr.a error.a substdio.a str.a wait.a 

except.0: \
except.1
	nroff -man except.1 > except.0

except.o: \
compile except.c fork.h strerr.h wait.h error.h exit.h
	./compile except.c

execcheck.o: \
compile execcheck.c execcheck.h case.h env.h qmail.h str.h stralloc.h
	./compile $(LDAPFLAGS) execcheck.c

fd.a: \
makelib fd_copy.o fd_move.o
	./makelib fd.a fd_copy.o fd_move.o

fd_copy.o: \
compile fd_copy.c fd.h
	./compile fd_copy.c

fd_move.o: \
compile fd_move.c fd.h
	./compile fd_move.c

fifo.o: \
compile fifo.c hasmkffo.h fifo.h
	./compile fifo.c

find-systype: \
find-systype.sh auto-ccld.sh
	cat auto-ccld.sh find-systype.sh > find-systype
	chmod 755 find-systype

fmt_str.o: \
compile fmt_str.c fmt.h
	./compile fmt_str.c

fmt_strn.o: \
compile fmt_strn.c fmt.h
	./compile fmt_strn.c

fmt_uint.o: \
compile fmt_uint.c fmt.h
	./compile fmt_uint.c

fmt_uint0.o: \
compile fmt_uint0.c fmt.h
	./compile fmt_uint0.c

fmt_ulong.o: \
compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

fmtqfn.o: \
compile fmtqfn.c fmtqfn.h fmt.h auto_split.h
	./compile fmtqfn.c

forgeries.0: \
forgeries.7
	nroff -man forgeries.7 > forgeries.0

fork.h: \
compile load tryvfork.c fork.h1 fork.h2
	( ( ./compile tryvfork.c && ./load tryvfork ) >/dev/null \
	2>&1 \
	&& cat fork.h2 || cat fork.h1 ) > fork.h
	rm -f tryvfork.o tryvfork

forward: \
load forward.o qmail.o strerr.a alloc.a fd.a wait.a sig.a env.a \
substdio.a error.a str.a fs.a auto_qmail.o
	./load forward qmail.o strerr.a alloc.a fd.a wait.a sig.a \
	env.a substdio.a error.a str.a fs.a auto_qmail.o 

forward.0: \
forward.1
	nroff -man forward.1 > forward.0

forward.o: \
compile forward.c sig.h readwrite.h exit.h env.h qmail.h substdio.h \
strerr.h substdio.h fmt.h
	./compile forward.c

fs.a: \
makelib fmt_str.o fmt_strn.o fmt_uint.o fmt_uint0.o fmt_ulong.o \
scan_ulong.o scan_8long.o
	./makelib fs.a fmt_str.o fmt_strn.o fmt_uint.o fmt_uint0.o \
	fmt_ulong.o scan_ulong.o scan_8long.o

getln.a: \
makelib getln.o getln2.o
	./makelib getln.a getln.o getln2.o

getln.o: \
compile getln.c substdio.h byte.h stralloc.h gen_alloc.h getln.h
	./compile getln.c

getln2.o: \
compile getln2.c substdio.h stralloc.h gen_alloc.h byte.h getln.h
	./compile getln2.c

getopt.a: \
makelib subgetopt.o sgetopt.o
	./makelib getopt.a subgetopt.o sgetopt.o

gfrom.o: \
compile gfrom.c str.h gfrom.h
	./compile gfrom.c

hasflock.h: \
tryflock.c compile load
	( ( ./compile tryflock.c && ./load tryflock ) >/dev/null \
	2>&1 \
	&& echo \#define HASFLOCK 1 || exit 0 ) > hasflock.h
	rm -f tryflock.o tryflock

hasmkffo.h: \
trymkffo.c compile load
	( ( ./compile trymkffo.c && ./load trymkffo ) >/dev/null \
	2>&1 \
	&& echo \#define HASMKFIFO 1 || exit 0 ) > hasmkffo.h
	rm -f trymkffo.o trymkffo

hasnpbg1.h: \
trynpbg1.c compile load open.h open.a fifo.h fifo.o select.h
	( ( ./compile trynpbg1.c \
	&& ./load trynpbg1 fifo.o open.a && ./trynpbg1 ) \
	>/dev/null 2>&1 \
	&& echo \#define HASNAMEDPIPEBUG1 1 || exit 0 ) > \
	hasnpbg1.h
	rm -f trynpbg1.o trynpbg1

hassalen.h: \
trysalen.c compile
	( ./compile trysalen.c >/dev/null 2>&1 \
	&& echo \#define HASSALEN 1 || exit 0 ) > hassalen.h
	rm -f trysalen.o

hassgact.h: \
trysgact.c compile load
	( ( ./compile trysgact.c && ./load trysgact ) >/dev/null \
	2>&1 \
	&& echo \#define HASSIGACTION 1 || exit 0 ) > hassgact.h
	rm -f trysgact.o trysgact

hassgprm.h: \
trysgprm.c compile load
	( ( ./compile trysgprm.c && ./load trysgprm ) >/dev/null \
	2>&1 \
	&& echo \#define HASSIGPROCMASK 1 || exit 0 ) > hassgprm.h
	rm -f trysgprm.o trysgprm

hasshsgr.h: \
chkshsgr warn-shsgr tryshsgr.c compile load
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	( ( ./compile tryshsgr.c \
	&& ./load tryshsgr && ./tryshsgr ) >/dev/null 2>&1 \
	&& echo \#define HASSHORTSETGROUPS 1 || exit 0 ) > \
	hasshsgr.h
	rm -f tryshsgr.o tryshsgr

haswaitp.h: \
trywaitp.c compile load
	( ( ./compile trywaitp.c && ./load trywaitp ) >/dev/null \
	2>&1 \
	&& echo \#define HASWAITPID 1 || exit 0 ) > haswaitp.h
	rm -f trywaitp.o trywaitp

headerbody.o: \
compile headerbody.c stralloc.h gen_alloc.h substdio.h getln.h \
hfield.h headerbody.h
	./compile headerbody.c

hfield.o: \
compile hfield.c hfield.h
	./compile hfield.c

hier.o: \
compile hier.c auto_qmail.h auto_split.h auto_uids.h fmt.h fifo.h
	./compile $(LDAPFLAGS) $(DEBUG) hier.c

home: \
home.sh conf-qmail
	cat home.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> home
	chmod 755 home

home+df: \
home+df.sh conf-qmail
	cat home+df.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> home+df
	chmod 755 home+df

hostname: \
load hostname.o substdio.a error.a str.a dns.lib socket.lib
	./load hostname substdio.a error.a str.a  `cat dns.lib` \
	`cat socket.lib`

hostname.o: \
compile hostname.c substdio.h subfd.h substdio.h readwrite.h exit.h
	./compile hostname.c

idedit: \
load idedit.o strerr.a substdio.a error.a str.a fs.a wait.a open.a \
seek.a
	./load idedit strerr.a substdio.a error.a str.a fs.a \
	wait.a open.a seek.a 

idedit.o: \
compile idedit.c readwrite.h exit.h scan.h fmt.h strerr.h open.h \
seek.h fork.h
	./compile idedit.c

install: \
load install.o fifo.o hier.o auto_qmail.o auto_split.o auto_uids.o \
auto_userl.o strerr.a substdio.a open.a error.a str.a fs.a
	./load install fifo.o hier.o auto_qmail.o auto_split.o \
	auto_uids.o auto_userl.o strerr.a substdio.a open.a error.a \
	str.a fs.a 

install-big: \
load install-big.o fifo.o install.o auto_qmail.o auto_split.o \
auto_uids.o auto_userl.o strerr.a substdio.a open.a error.a str.a fs.a
	./load install-big fifo.o install.o auto_qmail.o \
	auto_split.o auto_uids.o auto_userl.o strerr.a substdio.a \
	open.a error.a str.a fs.a 

install-big.o: \
compile install-big.c auto_qmail.h auto_split.h auto_uids.h fmt.h \
fifo.h
	./compile $(LDAPFLAGS) $(DEBUG) install-big.c

install.o: \
compile install.c substdio.h strerr.h error.h open.h readwrite.h \
exit.h
	./compile install.c

instcheck: \
load instcheck.o fifo.o hier.o auto_qmail.o auto_split.o auto_uids.o \
auto_userl.o strerr.a substdio.a error.a str.a fs.a
	./load instcheck fifo.o hier.o auto_qmail.o auto_split.o \
	auto_uids.o auto_userl.o strerr.a substdio.a error.a str.a fs.a 

instcheck.o: \
compile instcheck.c strerr.h error.h readwrite.h exit.h
	./compile instcheck.c

ip.o: \
compile ip.c fmt.h scan.h ip.h
	./compile ip.c

ipalloc.o: \
compile ipalloc.c alloc.h gen_allocdefs.h ip.h ipalloc.h ip.h \
gen_alloc.h
	./compile ipalloc.c

ipme.o: \
compile ipme.c hassalen.h byte.h ip.h ipalloc.h ip.h gen_alloc.h \
stralloc.h gen_alloc.h ipme.h ip.h
	./compile ipme.c

ipmeprint: \
load ipmeprint.o ipme.o ip.o ipalloc.o stralloc.a alloc.a substdio.a \
error.a str.a fs.a socket.lib
	./load ipmeprint ipme.o ip.o ipalloc.o stralloc.a alloc.a \
	substdio.a error.a str.a fs.a  `cat socket.lib`

ipmeprint.o: \
compile ipmeprint.c subfd.h substdio.h substdio.h ip.h ipme.h ip.h \
ip.h gen_alloc.h exit.h
	./compile ipmeprint.c

it: \
qmail-local qmail-lspawn qmail-getpw qmail-remote qmail-rspawn \
qmail-clean qmail-send qmail-start splogger qmail-queue qmail-inject \
predate datemail mailsubj qmail-upq qmail-showctl qmail-newu \
qmail-pw2u qmail-qread qmail-qstat qmail-tcpto qmail-tcpok \
qmail-pop3d qmail-popup qmail-qmqpc qmail-qmqpd qmail-qmtpd \
qmail-smtpd sendmail tcp-env qmail-newmrh config config-fast dnscname \
dnsptr dnsip dnsmxip dnsfq hostname ipmeprint qreceipt qsmhook qbiff \
forward preline condredirect bouncesaying except maildirmake \
maildir2mbox maildirwatch qail elq pinq idedit install-big \
install instcheck home home+df proc proc+df binm1 \
binm1+df binm2 binm2+df binm3 binm3+df

load: \
make-load warn-auto.sh systype
	( cat warn-auto.sh; ./make-load "`cat systype`" ) > load
	chmod 755 load

localdelivery.o: \
compile localdelivery.c localdelivery.h control.h qldap-debug.h
	./compile $(DEBUG) localdelivery.c

locallookup.o: \
compile locallookup.c locallookup.h checkpassword.h error.h getln.h \
localdelivery.h open.h passwd.h substdio.h
	./compile $(DEBUG) $(SHADOWOPTS) locallookup.c

lock.a: \
makelib lock_ex.o lock_exnb.o lock_un.o
	./makelib lock.a lock_ex.o lock_exnb.o lock_un.o

lock_ex.o: \
compile lock_ex.c hasflock.h lock.h
	./compile lock_ex.c

lock_exnb.o: \
compile lock_exnb.c hasflock.h lock.h
	./compile lock_exnb.c

lock_un.o: \
compile lock_un.c hasflock.h lock.h
	./compile lock_un.c

maildir.0: \
maildir.5
	nroff -man maildir.5 > maildir.0

maildir.o: \
compile maildir.c prioq.h datetime.h gen_alloc.h env.h stralloc.h \
gen_alloc.h direntry.h datetime.h now.h datetime.h str.h maildir.h \
strerr.h
	./compile maildir.c

maildir++.o: \
compile maildir++.c maildir++.h readwrite.h stralloc.h error.h str.h \
open.h substdio.h getln.h error.h strerr.h fmt.h scan.h now.h seek.h \
sig.h direntry.h
	./compile $(LDAPFLAGS) maildir++.c

maildir2mbox: \
load maildir2mbox.o maildir.o prioq.o now.o myctime.o gfrom.o lock.a \
getln.a env.a open.a strerr.a stralloc.a alloc.a substdio.a error.a \
str.a fs.a datetime.a
	./load maildir2mbox maildir.o prioq.o now.o myctime.o \
	gfrom.o lock.a getln.a env.a open.a strerr.a stralloc.a \
	alloc.a substdio.a error.a str.a fs.a datetime.a 

maildir2mbox.0: \
maildir2mbox.1
	nroff -man maildir2mbox.1 > maildir2mbox.0

maildir2mbox.o: \
compile maildir2mbox.c readwrite.h prioq.h datetime.h gen_alloc.h \
env.h stralloc.h gen_alloc.h subfd.h substdio.h substdio.h getln.h \
error.h open.h lock.h gfrom.h str.h exit.h myctime.h maildir.h \
strerr.h
	./compile maildir2mbox.c

maildirmake: \
load maildirmake.o strerr.a substdio.a error.a str.a
	./load maildirmake strerr.a substdio.a error.a str.a 

maildirmake.0: \
maildirmake.1
	nroff -man maildirmake.1 > maildirmake.0

maildirmake.o: \
compile maildirmake.c strerr.h exit.h
	./compile maildirmake.c

maildirwatch: \
load maildirwatch.o hfield.o headerbody.o maildir.o prioq.o now.o \
getln.a env.a open.a strerr.a stralloc.a alloc.a substdio.a error.a \
str.a
	./load maildirwatch hfield.o headerbody.o maildir.o \
	prioq.o now.o getln.a env.a open.a strerr.a stralloc.a \
	alloc.a substdio.a error.a str.a 

maildirwatch.0: \
maildirwatch.1
	nroff -man maildirwatch.1 > maildirwatch.0

maildirwatch.o: \
compile maildirwatch.c getln.h substdio.h subfd.h substdio.h prioq.h \
datetime.h gen_alloc.h stralloc.h gen_alloc.h str.h exit.h hfield.h \
readwrite.h open.h headerbody.h maildir.h strerr.h
	./compile maildirwatch.c

mailmagic.o: \
compile mailmagic.c mailmagic.h byte.h case.h error.h getln.h \
stralloc.h substdio.h qmail-ldap.h
	./compile $(LDAPFLAGS) mailmagic.c

mailmaker.o: \
compile mailmaker.c mailmaker.h error.h open.h qldap-errno.h
	./compile $(MDIRMAKE) mailmaker.c

mailsubj: \
warn-auto.sh mailsubj.sh conf-qmail conf-break conf-split
	cat warn-auto.sh mailsubj.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> mailsubj
	chmod 755 mailsubj

mailsubj.0: \
mailsubj.1
	nroff -man mailsubj.1 > mailsubj.0

make-compile: \
make-compile.sh auto-ccld.sh
	cat auto-ccld.sh make-compile.sh > make-compile
	chmod 755 make-compile

make-load: \
make-load.sh auto-ccld.sh
	cat auto-ccld.sh make-load.sh > make-load
	chmod 755 make-load

make-makelib: \
make-makelib.sh auto-ccld.sh
	cat auto-ccld.sh make-makelib.sh > make-makelib
	chmod 755 make-makelib

Makefile.cdb-p: \
Makefile.cdb conf-qmail
	cat Makefile.cdb \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> Makefile.cdb-p
	chmod 644 Makefile.cdb-p

makelib: \
make-makelib warn-auto.sh systype
	( cat warn-auto.sh; ./make-makelib "`cat systype`" ) > \
	makelib
	chmod 755 makelib

man: \
qmail-local.0 qmail-lspawn.0 qmail-getpw.0 qmail-remote.0 \
qmail-rspawn.0 qmail-clean.0 qmail-send.0 qmail-start.0 splogger.0 \
qmail-queue.0 qmail-inject.0 mailsubj.0 qmail-showctl.0 qmail-newu.0 \
qmail-pw2u.0 qmail-qread.0 qmail-qstat.0 qmail-tcpto.0 qmail-tcpok.0 \
qmail-pop3d.0 qmail-popup.0 qmail-qmqpc.0 qmail-qmqpd.0 qmail-qmtpd.0 \
qmail-smtpd.0 tcp-env.0 qmail-newmrh.0 qreceipt.0 qbiff.0 forward.0 \
preline.0 condredirect.0 bouncesaying.0 except.0 maildirmake.0 \
maildir2mbox.0 maildirwatch.0 qmail.0 qmail-limits.0 qmail-log.0 \
qmail-control.0 qmail-header.0 qmail-users.0 dot-qmail.0 \
qmail-command.0 tcp-environ.0 maildir.0 mbox.0 addresses.0 \
envelopes.0 forgeries.0

mbox.0: \
mbox.5
	nroff -man mbox.5 > mbox.0

myctime.o: \
compile myctime.c datetime.h fmt.h myctime.h
	./compile myctime.c

ndelay.a: \
makelib ndelay.o ndelay_off.o
	./makelib ndelay.a ndelay.o ndelay_off.o

ndelay.o: \
compile ndelay.c ndelay.h
	./compile ndelay.c

ndelay_off.o: \
compile ndelay_off.c ndelay.h
	./compile ndelay_off.c

newfield.o: \
compile newfield.c fmt.h datetime.h stralloc.h gen_alloc.h \
date822fmt.h newfield.h stralloc.h
	./compile newfield.c

now.o: \
compile now.c datetime.h now.h datetime.h
	./compile now.c

open.a: \
makelib open_append.o open_excl.o open_read.o open_trunc.o \
open_write.o
	./makelib open.a open_append.o open_excl.o open_read.o \
	open_trunc.o open_write.o

open_append.o: \
compile open_append.c open.h
	./compile open_append.c

open_excl.o: \
compile open_excl.c open.h
	./compile open_excl.c

open_read.o: \
compile open_read.c open.h
	./compile open_read.c

open_trunc.o: \
compile open_trunc.c open.h
	./compile open_trunc.c

open_write.o: \
compile open_write.c open.h
	./compile open_write.c

output.o: \
compile output.c output.h stralloc.h substdio.h fmt.h str.h scan.h \
readwrite.h
	./compile output.c

passwd.o: \
compile passwd.c base64.h byte.h case.h digest_md4.h digest_md5.h \
digest_rmd160.h digest_sha1.h qldap-debug.h qldap-errno.h str.h \
stralloc.h uint32.h passwd.h
	./compile $(LDAPFLAGS) $(DEBUG) passwd.c

pbsadd: \
load pbsadd.o control.o now.o ip.o getln.a open.a env.a stralloc.a \
alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o socket.lib
	./load pbsadd control.o now.o ip.o getln.a open.a env.a \
	stralloc.a alloc.a strerr.a substdio.a error.a str.a fs.a \
	auto_qmail.o `cat socket.lib`

pbsadd.o: \
compile pbsadd.c alloc.h auto_qmail.h byte.h control.h env.h error.h \
exit.h fmt.h ip.h now.h readwrite.h stralloc.h substdio.h
	./compile pbsadd.c

pbscheck: \
load pbscheck.o control.o now.o timeoutread.o timeoutwrite.o \
ip.o getln.a open.a env.a stralloc.a alloc.a strerr.a substdio.a \
error.a str.a fs.a auto_qmail.o socket.lib
	./load pbscheck control.o now.o timeoutread.o timeoutwrite.o \
	ip.o getln.a open.a env.a stralloc.a alloc.a strerr.a substdio.a \
	error.a str.a fs.a auto_qmail.o `cat socket.lib`

pbscheck.o: \
compile pbscheck.c alloc.h auto_qmail.h byte.h control.h env.h error.h \
exit.h fmt.h ip.h now.h readwrite.h str.h stralloc.h substdio.h timeoutread.h \
timeoutwrite.h
	./compile pbscheck.c

pbsdbd: \
load pbsdbd.o control.o now.o ip.o ndelay.a getln.a open.a stralloc.a \
alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o socket.lib
	./load pbsdbd control.o now.o ip.o ndelay.a getln.a open.a \
	stralloc.a alloc.a strerr.a substdio.a error.a str.a fs.a \
	auto_qmail.o `cat socket.lib`

pbsdbd.o: \
compile pbsdbd.c alloc.h auto_qmail.h byte.h control.h ip.h ndelay.h \
now.h stralloc.h strerr.h substdio.h uint32.h
	./compile pbsdbd.c

pbsexec.o: \
compile pbsexec.c pbsexec.h open.h qldap-debug.h wait.h
	./compile $(DEBUG) pbsexec.c

pinq: \
warn-auto.sh pinq.sh conf-qmail conf-break conf-split
	cat warn-auto.sh pinq.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> pinq
	chmod 755 pinq

predate: \
load predate.o datetime.a strerr.a sig.a fd.a wait.a substdio.a \
error.a str.a fs.a
	./load predate datetime.a strerr.a sig.a fd.a wait.a \
	substdio.a error.a str.a fs.a 

predate.o: \
compile predate.c datetime.h fork.h wait.h fd.h fmt.h strerr.h \
substdio.h subfd.h substdio.h readwrite.h exit.h
	./compile predate.c

preline: \
load preline.o strerr.a fd.a wait.a sig.a env.a getopt.a substdio.a \
error.a str.a
	./load preline strerr.a fd.a wait.a sig.a env.a getopt.a \
	substdio.a error.a str.a 

preline.0: \
preline.1
	nroff -man preline.1 > preline.0

preline.o: \
compile preline.c fd.h sgetopt.h subgetopt.h readwrite.h strerr.h \
substdio.h exit.h fork.h wait.h env.h sig.h error.h
	./compile preline.c

prioq.o: \
compile prioq.c alloc.h gen_allocdefs.h prioq.h datetime.h \
gen_alloc.h
	./compile prioq.c

proc: \
proc.sh conf-qmail
	cat proc.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> proc
	chmod 755 proc

proc+df: \
proc+df.sh conf-qmail
	cat proc+df.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	> proc+df
	chmod 755 proc+df

prot.o: \
compile prot.c hasshsgr.h prot.h
	./compile prot.c

qail: \
warn-auto.sh qail.sh conf-qmail conf-break conf-split
	cat warn-auto.sh qail.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> qail
	chmod 755 qail

qbiff: \
load qbiff.o headerbody.o hfield.o getln.a env.a open.a stralloc.a \
alloc.a substdio.a error.a str.a
	./load qbiff headerbody.o hfield.o getln.a env.a open.a \
	stralloc.a alloc.a substdio.a error.a str.a 

qbiff.0: \
qbiff.1
	nroff -man qbiff.1 > qbiff.0

qbiff.o: \
compile qbiff.c readwrite.h stralloc.h gen_alloc.h substdio.h subfd.h \
substdio.h open.h byte.h str.h headerbody.h hfield.h env.h exit.h
	./compile qbiff.c

qldap.a: \
makelib check.o output.o qldap.o qldap-cluster.o qldap-filter.o \
qldap-debug.o qldap-errno.o auto_break.o
	./makelib qldap.a check.o output.o qldap.o qldap-cluster.o \
	qldap-filter.o qldap-debug.o qldap-errno.o auto_break.o

qldap.o: \
compile qldap.c qldap.h alloc.h byte.h case.h check.h control.h error.h \
fmt.h qldap-debug.h qldap-errno.h qmail-ldap.h scan.h str.h stralloc.h
	./compile $(LDAPFLAGS) $(LDAPINCLUDES) $(DEBUG) qldap.c

qldap-cluster.o: \
compile qldap-cluster.c qldap-cluster.h constmap.h control.h qldap-debug.h \
stralloc.h
	./compile $(LDAPFLAGS) $(DEBUG) qldap-cluster.c

qldap-debug.o: \
compile qldap-debug.c output.h stralloc.h substdio.h fmt.h str.h readwrite.h \
error.h qldap-errno.h env.h scan.h qldap-debug.h
	./compile $(LDAPFLAGS) $(DEBUG) qldap-debug.c

qldap-errno.o: \
compile qldap-errno.c qldap-errno.h error.h
	./compile $(LDAPFLAGS) qldap-errno.c

qldap-filter.o: \
compile qldap-filter.c auto_break.h qldap.h qmail-ldap.h str.h stralloc.h
	./compile $(LDAPFLAGS) qldap-filter.c

profile: qldap-profile.o

qldap-profile.o: \
compile qldap-profile.c qldap-profile.h qldap-debug.h
	./compile $(INCTAI) $(DEBUG) qldap-profile.c 

qmail-cdb: \
load qmail-cdb.o getln.a open.a cdbmake.a seek.a case.a \
stralloc.a alloc.a strerr.a substdio.a error.a str.a auto_qmail.o
	./load qmail-cdb getln.a open.a cdbmake.a seek.a \
	case.a stralloc.a alloc.a strerr.a substdio.a error.a str.a \
	auto_qmail.o

qmail-cdb.o: \
compile qmail-cdb.c auto_qmail.h case.h cdb_make.h exit.h getln.h \
open.h readwrite.h stralloc.h strerr.h substdio.h uint32.h
	./compile qmail-cdb.c

qmail-clean: \
load qmail-clean.o fmtqfn.o now.o getln.a sig.a stralloc.a alloc.a \
substdio.a error.a str.a fs.a auto_qmail.o auto_split.o
	./load qmail-clean fmtqfn.o now.o getln.a sig.a stralloc.a \
	alloc.a substdio.a error.a str.a fs.a auto_qmail.o \
	auto_split.o 

qmail-clean.0: \
qmail-clean.8
	nroff -man qmail-clean.8 > qmail-clean.0

qmail-clean.o: \
compile qmail-clean.c readwrite.h sig.h now.h datetime.h str.h \
direntry.h getln.h stralloc.h gen_alloc.h substdio.h subfd.h \
substdio.h byte.h scan.h fmt.h error.h exit.h fmtqfn.h auto_qmail.h
	./compile $(LDAPFLAGS) qmail-clean.c

qmail-command.0: \
qmail-command.8
	nroff -man qmail-command.8 > qmail-command.0

qmail-control.0: \
qmail-control.5
	nroff -man qmail-control.5 > qmail-control.0

qmail-control.5: \
qmail-control.9 conf-break conf-spawn
	cat qmail-control.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-control.5

qmail-forward: \
load qmail-forward.o qmail.o control.o now.o env.a fd.a wait.a open.a getln.a \
seek.a stralloc.a alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o
	./load qmail-forward qmail.o control.o now.o env.a fd.a wait.a \
	open.a getln.a seek.a strerr.a stralloc.a alloc.a substdio.a \
	error.a str.a fs.a auto_qmail.o
	
qmail-forward.o: \
compile qmail-forward.c auto_qmail.h control.h error.h fmt.h getln.h now.h \
qmail.h seek.h str.h stralloc.h strerr.h substdio.h
	./compile $(LDAPFLAGS) qmail-forward.c
	
qmail-getpw: \
load qmail-getpw.o case.a substdio.a error.a str.a fs.a auto_break.o \
auto_usera.o
	./load qmail-getpw case.a substdio.a error.a str.a fs.a \
	auto_break.o auto_usera.o 

qmail-getpw.0: \
qmail-getpw.8
	nroff -man qmail-getpw.8 > qmail-getpw.0

qmail-getpw.8: \
qmail-getpw.9 conf-break conf-spawn
	cat qmail-getpw.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-getpw.8

qmail-getpw.o: \
compile qmail-getpw.c readwrite.h substdio.h subfd.h substdio.h \
error.h exit.h byte.h str.h case.h fmt.h auto_usera.h auto_break.h \
qlx.h
	./compile qmail-getpw.c

qmail-group: \
load qmail-group.o qmail.o now.o control.o case.a getln.a sig.a open.a \
seek.a fd.a wait.a env.a qldap.a read-ctrl.o stralloc.a alloc.a strerr.a \
substdio.a error.a fs.a str.a coe.o auto_qmail.o
	./load qmail-group qmail.o now.o control.o case.a getln.a sig.a \
	open.a seek.a fd.a wait.a env.a qldap.a read-ctrl.o stralloc.a \
	alloc.a fs.a strerr.a substdio.a error.a str.a coe.o auto_qmail.o \
	$(LDAPLIBS) 

qmail-group.o: \
compile qmail-group.c alloc.h auto_break.h byte.h case.h coe.h control.h \
env.h error.h fd.h fmt.h getln.h ndelay.h now.h open.h qldap.h qldap-errno.h \
qmail.h qmail-ldap.h read-ctrl.h seek.h sig.h str.h stralloc.h strerr.h \
substdio.h wait.h
	./compile $(LDAPFLAGS) qmail-group.c

qmail-header.0: \
qmail-header.5
	nroff -man qmail-header.5 > qmail-header.0

qmail-imapd-ssl.run: \
qmail-imapd-ssl.sh conf-qmail
	cat qmail-imapd-ssl.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-imapd-ssl.run
	chmod 755 qmail-imapd-ssl.run

qmail-imapd.run: \
qmail-imapd.sh conf-qmail
	cat qmail-imapd.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-imapd.run
	chmod 755 qmail-imapd.run

qmail-inject: \
load qmail-inject.o headerbody.o hfield.o newfield.o quote.o now.o \
control.o date822fmt.o constmap.o qmail.o case.a fd.a wait.a open.a \
getln.a sig.a getopt.a datetime.a token822.o env.a stralloc.a alloc.a \
substdio.a error.a str.a fs.a auto_qmail.o
	./load qmail-inject headerbody.o hfield.o newfield.o \
	quote.o now.o control.o date822fmt.o constmap.o qmail.o \
	case.a fd.a wait.a open.a getln.a sig.a getopt.a datetime.a \
	token822.o env.a stralloc.a alloc.a substdio.a error.a \
	str.a fs.a auto_qmail.o 

qmail-inject.0: \
qmail-inject.8
	nroff -man qmail-inject.8 > qmail-inject.0

qmail-inject.o: \
compile qmail-inject.c sig.h substdio.h stralloc.h gen_alloc.h \
subfd.h substdio.h sgetopt.h subgetopt.h getln.h alloc.h str.h fmt.h \
hfield.h token822.h gen_alloc.h control.h env.h gen_alloc.h \
gen_allocdefs.h error.h qmail.h substdio.h now.h datetime.h exit.h \
quote.h headerbody.h auto_qmail.h newfield.h stralloc.h constmap.h
	./compile qmail-inject.c

qmail-limits.0: \
qmail-limits.7
	nroff -man qmail-limits.7 > qmail-limits.0

qmail-limits.7: \
qmail-limits.9 conf-break conf-spawn
	cat qmail-limits.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-limits.7

qmail-local: \
load qmail-local.o qmail.o quote.o now.o gfrom.o myctime.o mailmaker.o \
slurpclose.o case.a getln.a getopt.a sig.a open.a seek.a lock.a fd.a \
wait.a env.a stralloc.a alloc.a strerr.a substdio.a error.a str.a \
fs.a datetime.a auto_qmail.o auto_patrn.o control.o socket.lib \
maildir++.o qldap-errno.o
	./load qmail-local qmail.o quote.o maildir++.o now.o gfrom.o \
	myctime.o mailmaker.o slurpclose.o case.a getln.a getopt.a sig.a \
	open.a seek.a lock.a fd.a wait.a env.a stralloc.a alloc.a strerr.a \
	substdio.a qldap-errno.o error.a str.a fs.a datetime.a auto_qmail.o \
	auto_patrn.o `cat socket.lib`

qmail-local.0: \
qmail-local.8
	nroff -man qmail-local.8 > qmail-local.0

qmail-local.o: \
compile qmail-local.c readwrite.h sig.h env.h byte.h exit.h fork.h \
open.h wait.h lock.h seek.h substdio.h getln.h strerr.h subfd.h \
sgetopt.h subgetopt.h alloc.h error.h stralloc.h gen_alloc.h fmt.h \
str.h now.h case.h quote.h qmail.h slurpclose.h myctime.h gfrom.h \
auto_patrn.h qmail-ldap.h qldap-errno.h auto_qmail.h scan.h maildir++.h \
mailmaker.h
	./compile $(LDAPFLAGS) $(MDIRMAKE) qmail-local.c

qmail-log.0: \
qmail-log.5
	nroff -man qmail-log.5 > qmail-log.0

qmail-ldaplookup: \
load qmail-ldaplookup.o qldap.a passwd.o digest_md4.o digest_md5.o \
digest_rmd160.o digest_sha1.o base64.o constmap.o localdelivery.o \
dirmaker.o wait.a read-ctrl.o control.o env.a getopt.a getln.a stralloc.a \
alloc.a strerr.a error.a substdio.a open.a fs.a str.a case.a auto_usera.o \
auto_qmail.o
	./load qmail-ldaplookup qldap.a passwd.o digest_md4.o digest_md5.o \
	digest_rmd160.o digest_sha1.o base64.o constmap.o localdelivery.o \
	dirmaker.o wait.a read-ctrl.o control.o env.a getopt.a getln.a \
	stralloc.a alloc.a strerr.a error.a substdio.a open.a fs.a str.a \
	case.a auto_usera.o auto_qmail.o $(LDAPLIBS) $(SHADOWLIBS)

qmail-ldaplookup.o: \
compile qmail-ldaplookup.c alloc.h auto_usera.h byte.h case.h env.h error.h \
localdelivery.h output.h passwd.h qldap.h qldap-cluster.h qldap-debug.h \
qldap-errno.h qmail-ldap.h read-ctrl.h scan.h sgetopt.h str.h stralloc.h \
strerr.h subfd.h substdio.h dirmaker.h
	./compile $(LDAPFLAGS) $(SHADOWOPTS) $(HDIRMAKE) $(DEBUG) \
	qmail-ldaplookup.c

qmail-lspawn: \
load qmail-lspawn.o spawn.o prot.o slurpclose.o coe.o control.o \
sig.a strerr.a getln.a wait.a case.a cdb.a fd.a open.a stralloc.a \
alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_uids.o \
auto_spawn.o auto_usera.o env.a qldap.a dirmaker.o read-ctrl.o \
localdelivery.o seek.a constmap.o
	./load qmail-lspawn spawn.o prot.o slurpclose.o coe.o control.o \
	qldap.a sig.a strerr.a constmap.o getln.a wait.a case.a cdb.a \
	fd.a seek.a open.a dirmaker.o read-ctrl.o localdelivery.o env.a \
	stralloc.a alloc.a substdio.a str.a error.a fs.a auto_qmail.o \
	auto_uids.o auto_usera.o auto_spawn.o $(LDAPLIBS)

qmail-lspawn.0: \
qmail-lspawn.8
	nroff -man qmail-lspawn.8 > qmail-lspawn.0

qmail-lspawn.o: \
compile qmail-lspawn.c fd.h wait.h prot.h substdio.h stralloc.h \
gen_alloc.h scan.h exit.h fork.h error.h cdb.h uint32.h case.h \
slurpclose.h auto_qmail.h auto_uids.h qlx.h \
auto_break.h auto_usera.h byte.h check.h env.h fmt.h localdelivery.h \
open.h qldap.h qldap-debug.h qldap-errno.h qmail-ldap.h read-ctrl.h \
sig.h str.h qldap-cluster.h getln.h seek.h dirmaker.h
	./compile $(LDAPFLAGS) $(HDIRMAKE) $(LDAPINCLUDES) $(DEBUG) \
	qmail-lspawn.c

qmail-newmrh: \
load qmail-newmrh.o getln.a open.a cdbmake.a seek.a case.a \
stralloc.a alloc.a strerr.a substdio.a error.a str.a auto_qmail.o
	./load qmail-newmrh getln.a open.a cdbmake.a seek.a \
	case.a stralloc.a alloc.a strerr.a substdio.a error.a \
	str.a auto_qmail.o 

qmail-newmrh.0: \
qmail-newmrh.8
	nroff -man qmail-newmrh.8 > qmail-newmrh.0

qmail-newmrh.8: \
qmail-newmrh.9 conf-break conf-spawn
	cat qmail-newmrh.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-newmrh.8

qmail-newmrh.o: \
compile qmail-newmrh.c strerr.h stralloc.h gen_alloc.h substdio.h \
getln.h exit.h readwrite.h open.h auto_qmail.h cdb_make.h uint32.h \
substdio.h
	./compile qmail-newmrh.c

qmail-newu: \
load qmail-newu.o getln.a open.a seek.a cdbmake.a case.a \
stralloc.a alloc.a substdio.a error.a str.a auto_qmail.o
	./load qmail-newu getln.a open.a cdbmake.a seek.a \
	case.a stralloc.a alloc.a substdio.a error.a str.a \
	auto_qmail.o 

qmail-newu.0: \
qmail-newu.8
	nroff -man qmail-newu.8 > qmail-newu.0

qmail-newu.8: \
qmail-newu.9 conf-break conf-spawn
	cat qmail-newu.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-newu.8

qmail-newu.o: \
compile qmail-newu.c stralloc.h gen_alloc.h subfd.h substdio.h \
getln.h substdio.h cdb_make.h uint32.h substdio.h exit.h readwrite.h \
open.h error.h case.h auto_qmail.h
	./compile qmail-newu.c

qmail-pbsdbd.run: \
qmail-pbsdbd.sh conf-qmail
	cat qmail-pbsdbd.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-pbsdbd.run
	chmod 755 qmail-pbsdbd.run

qmail-pop3d: \
load qmail-pop3d.o commands.o case.a timeoutread.o timeoutwrite.o \
maildir.o prioq.o now.o env.a strerr.a sig.a open.a getln.a str.a \
stralloc.a alloc.a substdio.a error.a fs.a socket.lib maildir++.o \
seek.a
	./load qmail-pop3d commands.o maildir++.o case.a timeoutread.o \
	timeoutwrite.o maildir.o prioq.o now.o env.a strerr.a sig.a \
	open.a getln.a stralloc.a alloc.a substdio.a error.a str.a \
	fs.a  seek.a `cat socket.lib`

qmail-pop3d.0: \
qmail-pop3d.8
	nroff -man qmail-pop3d.8 > qmail-pop3d.0

qmail-pop3d.o: \
compile qmail-pop3d.c commands.h sig.h getln.h stralloc.h gen_alloc.h \
substdio.h alloc.h open.h prioq.h datetime.h gen_alloc.h scan.h fmt.h \
str.h exit.h maildir.h strerr.h readwrite.h timeoutread.h \
timeoutwrite.h maildir++.h
	./compile $(LDAPFLAGS) $(MNW) qmail-pop3d.c

qmail-pop3d-ssl.run: \
qmail-pop3d-ssl.sh conf-qmail
	cat qmail-pop3d-ssl.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-pop3d-ssl.run
	chmod 755 qmail-pop3d-ssl.run

qmail-pop3d.run: \
qmail-pop3d.sh conf-qmail
	cat qmail-pop3d.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-pop3d.run
	chmod 755 qmail-pop3d.run

qmail-popup: \
load qmail-popup.o commands.o timeoutread.o timeoutwrite.o now.o \
case.a fd.a sig.a wait.a stralloc.a alloc.a substdio.a error.a str.a \
fs.a socket.lib
	./load qmail-popup commands.o timeoutread.o timeoutwrite.o \
	now.o case.a fd.a sig.a wait.a stralloc.a alloc.a \
	substdio.a error.a str.a fs.a  `cat socket.lib`

qmail-popup.0: \
qmail-popup.8
	nroff -man qmail-popup.8 > qmail-popup.0

qmail-popup.o: \
compile qmail-popup.c commands.h fd.h sig.h stralloc.h gen_alloc.h \
substdio.h alloc.h wait.h str.h byte.h now.h datetime.h fmt.h exit.h \
readwrite.h timeoutread.h timeoutwrite.h
	./compile $(DEBUG) qmail-popup.c

qmail-pw2u: \
load qmail-pw2u.o constmap.o control.o open.a getln.a case.a getopt.a \
stralloc.a alloc.a substdio.a error.a str.a fs.a auto_usera.o \
auto_break.o auto_qmail.o
	./load qmail-pw2u constmap.o control.o open.a getln.a \
	case.a getopt.a stralloc.a alloc.a substdio.a error.a str.a \
	fs.a auto_usera.o auto_break.o auto_qmail.o 

qmail-pw2u.0: \
qmail-pw2u.8
	nroff -man qmail-pw2u.8 > qmail-pw2u.0

qmail-pw2u.8: \
qmail-pw2u.9 conf-break conf-spawn
	cat qmail-pw2u.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-pw2u.8

qmail-pw2u.o: \
compile qmail-pw2u.c substdio.h readwrite.h subfd.h substdio.h \
sgetopt.h subgetopt.h control.h constmap.h stralloc.h gen_alloc.h \
fmt.h str.h scan.h open.h error.h getln.h auto_break.h auto_qmail.h \
auto_usera.h
	./compile qmail-pw2u.c

qmail-qmqpc: \
load qmail-qmqpc.o slurpclose.o timeoutread.o timeoutwrite.o \
timeoutconn.o ip.o control.o auto_qmail.o sig.a ndelay.a open.a \
getln.a substdio.a stralloc.a alloc.a error.a str.a fs.a socket.lib \
dns.lib
	./load qmail-qmqpc slurpclose.o timeoutread.o \
	timeoutwrite.o timeoutconn.o ip.o control.o auto_qmail.o \
	sig.a ndelay.a open.a getln.a substdio.a stralloc.a alloc.a \
	error.a fs.a dns.o str.a ipalloc.o `cat dns.lib` `cat socket.lib` \
	$(ZLIB)

qmail-qmqpc.0: \
qmail-qmqpc.8
	nroff -man qmail-qmqpc.8 > qmail-qmqpc.0

qmail-qmqpc.o: \
compile qmail-qmqpc.c substdio.h getln.h readwrite.h exit.h \
stralloc.h gen_alloc.h slurpclose.h error.h sig.h ip.h timeoutconn.h \
timeoutread.h timeoutwrite.h auto_qmail.h control.h fmt.h ipalloc.h
	./compile $(LDAPFLAGS) $(ZINCLUDES) qmail-qmqpc.c

qmail-qmqpd: \
load qmail-qmqpd.o received.o now.o date822fmt.o qmail.o auto_qmail.o \
env.a substdio.a sig.a error.a wait.a fd.a str.a datetime.a fs.a
	./load qmail-qmqpd received.o now.o date822fmt.o qmail.o \
	auto_qmail.o env.a substdio.a sig.a error.a wait.a fd.a \
	str.a datetime.a fs.a $(ZLIB)

qmail-qmqpd.0: \
qmail-qmqpd.8
	nroff -man qmail-qmqpd.8 > qmail-qmqpd.0

qmail-qmqpd.o: \
compile qmail-qmqpd.c auto_qmail.h qmail.h substdio.h received.h \
sig.h substdio.h readwrite.h exit.h now.h datetime.h fmt.h env.h
	./compile $(LDAPFLAGS) $(ZINCLUDES) qmail-qmqpd.c

qmail-qmqpd.run: \
qmail-qmqpd.sh conf-qmail
	cat qmail-qmqpd.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-qmqpd.run
	chmod 755 qmail-qmqpd.run

qmail-qmtpd: \
load qmail-qmtpd.o rcpthosts.o control.o constmap.o received.o \
date822fmt.o now.o qmail.o cdb.a fd.a seek.a wait.a datetime.a \
open.a getln.a sig.a case.a env.a stralloc.a alloc.a substdio.a \
error.a str.a fs.a auto_qmail.o
	./load qmail-qmtpd rcpthosts.o control.o constmap.o \
	received.o date822fmt.o now.o qmail.o cdb.a fd.a seek.a \
	wait.a datetime.a open.a getln.a sig.a case.a env.a \
	stralloc.a alloc.a substdio.a error.a str.a fs.a auto_qmail.o 

qmail-qmtpd.0: \
qmail-qmtpd.8
	nroff -man qmail-qmtpd.8 > qmail-qmtpd.0

qmail-qmtpd.o: \
compile qmail-qmtpd.c stralloc.h gen_alloc.h substdio.h qmail.h \
substdio.h now.h datetime.h str.h fmt.h env.h sig.h rcpthosts.h \
auto_qmail.h readwrite.h control.h received.h
	./compile qmail-qmtpd.c

qmail-qread: \
load qmail-qread.o fmtqfn.o readsubdir.o date822fmt.o datetime.a \
open.a getln.a stralloc.a alloc.a substdio.a error.a str.a fs.a \
auto_qmail.o auto_split.o
	./load qmail-qread fmtqfn.o readsubdir.o date822fmt.o \
	datetime.a open.a getln.a stralloc.a alloc.a substdio.a \
	error.a str.a fs.a auto_qmail.o auto_split.o 

qmail-qread.0: \
qmail-qread.8
	nroff -man qmail-qread.8 > qmail-qread.0

qmail-qread.o: \
compile qmail-qread.c stralloc.h gen_alloc.h substdio.h subfd.h \
substdio.h fmt.h str.h getln.h fmtqfn.h readsubdir.h direntry.h \
auto_qmail.h open.h datetime.h date822fmt.h readwrite.h error.h \
exit.h
	./compile qmail-qread.c

qmail-qstat: \
warn-auto.sh qmail-qstat.sh conf-qmail conf-break conf-split
	cat warn-auto.sh qmail-qstat.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> qmail-qstat
	chmod 755 qmail-qstat

qmail-qstat.0: \
qmail-qstat.8
	nroff -man qmail-qstat.8 > qmail-qstat.0

qmail-queue: \
load qmail-queue.o triggerpull.o fmtqfn.o now.o date822fmt.o \
datetime.a seek.a ndelay.a open.a sig.a alloc.a substdio.a error.a \
str.a fs.a auto_qmail.o auto_split.o auto_uids.o control.o constmap.o \
stralloc.a case.a getln.a
	./load qmail-queue triggerpull.o fmtqfn.o now.o control.o \
	constmap.o date822fmt.o datetime.a seek.a ndelay.a open.a sig.a \
	stralloc.a getln.a case.a alloc.a substdio.a error.a str.a fs.a \
	auto_qmail.o auto_split.o auto_uids.o 

qmail-queue.0: \
qmail-queue.8
	nroff -man qmail-queue.8 > qmail-queue.0

qmail-queue.o: \
compile qmail-queue.c readwrite.h sig.h exit.h open.h seek.h fmt.h \
alloc.h substdio.h datetime.h now.h datetime.h triggerpull.h extra.h \
auto_qmail.h auto_uids.h date822fmt.h fmtqfn.h
	./compile $(LDAPFLAGS) qmail-queue.c

qmail-quotawarn: \
load qmail-quotawarn.o newfield.o now.o date822fmt.o mailmagic.o case.a \
control.o fd.a wait.a open.a myctime.o case.a getln.a sig.a open.a seek.a \
lock.a datetime.a env.a stralloc.a alloc.a strerr.a substdio.a error.a str.a \
fs.a auto_qmail.o
	./load qmail-quotawarn newfield.o now.o date822fmt.o mailmagic.o \
	case.a control.o fd.a wait.a open.a myctime.o case.a getln.a sig.a \
	open.a seek.a lock.a datetime.a env.a stralloc.a alloc.a strerr.a \
	substdio.a error.a str.a fs.a auto_qmail.o

qmail-quotawarn.o: \
compile qmail-quotawarn.c auto_qmail.h byte.h case.h control.h date822fmt.h \
datetime.h env.h error.h exit.h fmt.h getln.h mailmagic.h myctime.h \
newfield.h now.h open.h qmail-ldap.h seek.h sig.h str.h strerr.h substdio.h \
wait.h lock.h
	./compile qmail-quotawarn.c

qmail-remote: \
load qmail-remote.o control.o constmap.o timeoutread.o timeoutwrite.o \
timeoutconn.o tcpto.o now.o dns.o ip.o ipalloc.o ipme.o quote.o xtext.o \
base64.o ndelay.a case.a sig.a open.a lock.a seek.a getln.a stralloc.a \
alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o \
dns.lib socket.lib
	./load qmail-remote control.o constmap.o timeoutread.o \
	timeoutwrite.o timeoutconn.o tcpto.o now.o dns.o ip.o \
	ipalloc.o ipme.o quote.o xtext.o base64.o ndelay.a case.a \
	sig.a open.a lock.a seek.a getln.a stralloc.a alloc.a \
	strerr.a substdio.a error.a str.a fs.a auto_qmail.o \
	`cat dns.lib` `cat socket.lib` $(TLSLIBS) $(ZLIB)

qmail-remote.0: \
qmail-remote.8
	nroff -man qmail-remote.8 > qmail-remote.0

qmail-remote.o: \
compile qmail-remote.c sig.h stralloc.h gen_alloc.h substdio.h \
subfd.h substdio.h scan.h case.h error.h auto_qmail.h control.h dns.h \
alloc.h quote.h ip.h ipalloc.h ip.h gen_alloc.h ipme.h ip.h ipalloc.h \
gen_alloc.h gen_allocdefs.h str.h now.h datetime.h exit.h constmap.h \
tcpto.h readwrite.h timeoutconn.h timeoutread.h timeoutwrite.h
	./compile $(LDAPFLAGS) $(TLS) $(TLSINCLUDES) $(ZINCLUDES) \
	qmail-remote.c

qmail-reply: \
load qmail-reply.o mailmagic.o case.a control.o constmap.o getln.a \
sig.a newfield.o now.o date822fmt.o datetime.a open.a seek.a env.a \
qmail.o getopt.a fd.a wait.a digest_md5.o base64.o stralloc.a alloc.a \
strerr.a substdio.a error.a str.a fs.a auto_qmail.o
	./load qmail-reply mailmagic.o case.a control.o constmap.o \
	getln.a sig.a newfield.o now.o date822fmt.o datetime.a open.a \
	seek.a env.a qmail.o getopt.a fd.a wait.a digest_md5.o base64.o \
	stralloc.a alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o

qmail-reply.o: \
compile qmail-reply.c byte.h case.h control.h constmap.h direntry.h env.h \
error.h exit.h getln.h newfield.h now.h open.h qmail.h qmail-ldap.h \
readwrite.h seek.h sgetopt.h strerr.h stralloc.h substdio.h uint32.h
	./compile $(LDAPFLAGS) qmail-reply.c

qmail-rspawn: \
load qmail-rspawn.o spawn.o tcpto_clean.o now.o coe.o sig.a open.a \
seek.a lock.a wait.a fd.a stralloc.a alloc.a substdio.a error.a str.a \
auto_qmail.o auto_uids.o auto_spawn.o
	./load qmail-rspawn spawn.o tcpto_clean.o now.o coe.o \
	sig.a open.a seek.a lock.a wait.a fd.a stralloc.a alloc.a \
	substdio.a error.a str.a auto_qmail.o auto_uids.o \
	auto_spawn.o 

qmail-rspawn.0: \
qmail-rspawn.8
	nroff -man qmail-rspawn.8 > qmail-rspawn.0

qmail-rspawn.o: \
compile qmail-rspawn.c fd.h wait.h substdio.h exit.h fork.h error.h \
tcpto.h
	./compile qmail-rspawn.c

qmail-secretary: \
load qmail-secretary.o base64.o digest_sha1.o control.o newfield.o now.o \
date822fmt.o datetime.a mailmaker.o mailmagic.o case.a getln.a qmail.o \
quote.o getopt.a seek.a fd.a wait.a sig.a open.a stralloc.a env.a alloc.a \
strerr.a substdio.a error.a str.a fs.a auto_qmail.o
	./load qmail-secretary base64.o digest_sha1.o control.o newfield.o \
	now.o date822fmt.o datetime.a mailmaker.o mailmagic.o case.a getln.a \
	qmail.o quote.o getopt.a seek.a fd.a wait.a sig.a open.a stralloc.a \
	env.a alloc.a strerr.a substdio.a error.a str.a fs.a auto_qmail.o
	
qmail-secretary.o: \
compile qmail-secretary.c uint32.h base64.h byte.h case.h digest_sha1.h \
direntry.h env.h error.h fd.h fmt.h getln.h mailmagic.h newfield.h now.h \
open.h qmail.h quote.h readwrite.h seek.h sgetopt.h sig.h str.h stralloc.h \
strerr.h substdio.h wait.h qldap-errno.h mailmaker.h
	./compile $(LDAPFLAGS) $(MDIRMAKE) qmail-secretary.c

qmail-send: \
load qmail-send.o qsutil.o control.o constmap.o newfield.o prioq.o \
trigger.o fmtqfn.o quote.o now.o readsubdir.o qmail.o date822fmt.o \
datetime.a case.a ndelay.a getln.a wait.a cdb.a seek.a fd.a sig.a \
open.a lock.a stralloc.a env.a alloc.a substdio.a error.a str.a fs.a \
auto_qmail.o auto_split.o
	./load qmail-send qsutil.o control.o constmap.o newfield.o \
	prioq.o trigger.o fmtqfn.o quote.o now.o readsubdir.o \
	qmail.o date822fmt.o datetime.a case.a ndelay.a getln.a \
	wait.a cdb.a seek.a fd.a sig.a open.a lock.a stralloc.a env.a \
	alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_split.o 

qmail-send.0: \
qmail-send.8
	nroff -man qmail-send.8 > qmail-send.0

qmail-send.8: \
qmail-send.9 conf-break conf-spawn
	cat qmail-send.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-send.8

qmail-send.o: \
compile qmail-send.c readwrite.h sig.h direntry.h control.h select.h \
open.h seek.h exit.h lock.h ndelay.h now.h datetime.h getln.h \
substdio.h alloc.h error.h stralloc.h gen_alloc.h str.h byte.h fmt.h \
scan.h case.h auto_qmail.h trigger.h newfield.h stralloc.h quote.h \
qmail.h substdio.h qsutil.h prioq.h datetime.h gen_alloc.h constmap.h \
fmtqfn.h readsubdir.h direntry.h cdb.h uint32.h
	./compile $(LDAPFLAGS) qmail-send.c

qmail-showctl: \
load qmail-showctl.o auto_uids.o control.o open.a getln.a stralloc.a \
alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_break.o \
auto_patrn.o auto_spawn.o auto_split.o
	./load qmail-showctl auto_uids.o control.o open.a getln.a \
	stralloc.a alloc.a substdio.a error.a str.a fs.a \
	auto_qmail.o auto_break.o auto_patrn.o auto_spawn.o \
	auto_split.o 

qmail-showctl.0: \
qmail-showctl.8
	nroff -man qmail-showctl.8 > qmail-showctl.0

qmail-showctl.o: \
compile qmail-showctl.c substdio.h subfd.h substdio.h exit.h fmt.h \
str.h control.h constmap.h stralloc.h gen_alloc.h direntry.h \
auto_uids.h auto_qmail.h auto_break.h auto_patrn.h auto_spawn.h \
auto_split.h
	./compile qmail-showctl.c

qmail-smtpd: \
load qmail-smtpd.o rcpthosts.o commands.o timeoutread.o rbl.o \
timeoutwrite.o ip.o ipme.o ipalloc.o control.o constmap.o received.o \
date822fmt.o now.o qmail.o execcheck.o cdb.a smtpcall.o coe.o fd.a \
seek.a wait.a datetime.a getln.a open.a sig.a case.a env.a stralloc.a \
alloc.a substdio.a error.a str.a fs.a auto_qmail.o auto_break.o \
dns.lib socket.lib
	./load qmail-smtpd rcpthosts.o commands.o timeoutread.o rbl.o \
	timeoutwrite.o ip.o ipme.o ipalloc.o control.o constmap.o \
	received.o date822fmt.o now.o qmail.o execcheck.o cdb.a \
	smtpcall.o coe.o fd.a seek.a wait.a datetime.a getln.a \
	open.a sig.a case.a env.a stralloc.a alloc.a substdio.a \
	error.a fs.a auto_qmail.o dns.o str.a auto_break.o \
	`cat dns.lib` `cat socket.lib` $(TLSLIBS) $(ZLIB)

qmail-smtpd.0: \
qmail-smtpd.8
	nroff -man qmail-smtpd.8 > qmail-smtpd.0

qmail-smtpd.o: \
compile qmail-smtpd.c sig.h readwrite.h stralloc.h gen_alloc.h \
substdio.h alloc.h auto_qmail.h control.h received.h constmap.h \
error.h ipme.h ip.h ipalloc.h ip.h gen_alloc.h ip.h qmail.h \
substdio.h str.h fmt.h scan.h byte.h case.h env.h now.h datetime.h \
exit.h rcpthosts.h timeoutread.h timeoutwrite.h commands.h rbl.h \
qmail-ldap.h auto_break.h
	./compile $(LDAPFLAGS) $(TLS) $(TLSINCLUDES) $(ZINCLUDES) \
	qmail-smtpd.c

qmail-smtpd.run: \
qmail-smtpd.sh conf-qmail
	cat qmail-smtpd.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail-smtpd.run
	chmod 755 qmail-smtpd.run

qmail-start: \
load qmail-start.o prot.o fd.a auto_uids.o
	./load qmail-start prot.o fd.a auto_uids.o 

qmail-start.0: \
qmail-start.8
	nroff -man qmail-start.8 > qmail-start.0

qmail-start.8: \
qmail-start.9 conf-break conf-spawn
	cat qmail-start.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-start.8

qmail-start.o: \
compile qmail-start.c fd.h prot.h exit.h fork.h auto_uids.h
	./compile $(LDAPFLAGS) qmail-start.c

qmail-tcpok: \
load qmail-tcpok.o open.a lock.a strerr.a substdio.a error.a str.a \
auto_qmail.o
	./load qmail-tcpok open.a lock.a strerr.a substdio.a \
	error.a str.a auto_qmail.o 

qmail-tcpok.0: \
qmail-tcpok.8
	nroff -man qmail-tcpok.8 > qmail-tcpok.0

qmail-tcpok.o: \
compile qmail-tcpok.c strerr.h substdio.h lock.h open.h readwrite.h \
auto_qmail.h exit.h
	./compile qmail-tcpok.c

qmail-tcpto: \
load qmail-tcpto.o ip.o now.o open.a lock.a substdio.a error.a str.a \
fs.a auto_qmail.o
	./load qmail-tcpto ip.o now.o open.a lock.a substdio.a \
	error.a str.a fs.a auto_qmail.o 

qmail-tcpto.0: \
qmail-tcpto.8
	nroff -man qmail-tcpto.8 > qmail-tcpto.0

qmail-tcpto.o: \
compile qmail-tcpto.c substdio.h subfd.h substdio.h auto_qmail.h \
fmt.h ip.h lock.h error.h exit.h datetime.h now.h datetime.h
	./compile qmail-tcpto.c

qmail-todo: \
load qmail-todo.o control.o constmap.o trigger.o fmtqfn.o now.o \
readsubdir.o case.a ndelay.a getln.a sig.a cdb.a open.a stralloc.a \
alloc.a substdio.a error.a str.a seek.a fs.a auto_qmail.o auto_split.o
	./load qmail-todo control.o constmap.o trigger.o fmtqfn.o now.o \
	readsubdir.o case.a ndelay.a getln.a sig.a cdb.a open.a stralloc.a \
	alloc.a substdio.a error.a str.a seek.a fs.a auto_qmail.o auto_split.o

qmail-todo.o: \
compile qmail-todo.c alloc.h auto_qmail.h byte.h cdb.h constmap.h control.h \
direntry.h error.h exit.h fmt.h fmtqfn.h getln.h open.h ndelay.h now.h \
readsubdir.h scan.h select.h sig.h str.h stralloc.h substdio.h trigger.h
	./compile $(LDAPFLAGS) qmail-todo.c

qmail-upq: \
warn-auto.sh qmail-upq.sh conf-qmail conf-break conf-split
	cat warn-auto.sh qmail-upq.sh \
	| sed s}QMAIL}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPLIT}"`head -1 conf-split`"}g \
	> qmail-upq
	chmod 755 qmail-upq

qmail-users.0: \
qmail-users.5
	nroff -man qmail-users.5 > qmail-users.0

qmail-users.5: \
qmail-users.9 conf-break conf-spawn
	cat qmail-users.9 \
	| sed s}QMAILHOME}"`head -1 conf-qmail`"}g \
	| sed s}BREAK}"`head -1 conf-break`"}g \
	| sed s}SPAWN}"`head -1 conf-spawn`"}g \
	> qmail-users.5

qmail-verify: \
load qmail-verify.o qldap.a read-ctrl.o control.o getln.a substdio.a \
stralloc.a env.a alloc.a error.a open.a fs.a case.a cdb.a str.a timeoutread.o \
localdelivery.o auto_qmail.o
	./load qmail-verify qldap.a read-ctrl.o control.o getln.a \
	substdio.a stralloc.a env.a alloc.a error.a open.a fs.a case.a \
	cdb.a str.a seek.a timeoutread.o localdelivery.o auto_qmail.o \
	$(LDAPLIBS)

qmail-verify.o: \
compile qmail-verify.c auto_break.h byte.h case.h cdb.h error.h getln.h \
localdelivery.h open.h output.h qldap.h qldap-debug.h qldap-errno.h \
qmail-ldap.h read-ctrl.h str.h stralloc.h subfd.h substdio.h \
timeoutread.h
	./compile $(LDAPFLAGS) $(DEBUG) qmail-verify.c

qmail.0: \
qmail.7
	nroff -man qmail.7 > qmail.0

qmail.o: \
compile qmail.c substdio.h readwrite.h wait.h exit.h fork.h fd.h \
qmail.h substdio.h auto_qmail.h
	./compile $(LDAPFLAGS) qmail.c

qmail.run: \
qmail.sh conf-qmail
	cat qmail.sh \
	| sed s}%QMAIL%}"`head -1 conf-qmail`"}g \
	> qmail.run
	chmod 755 qmail.run

qreceipt: \
load qreceipt.o headerbody.o hfield.o quote.o token822.o qmail.o \
getln.a fd.a wait.a sig.a env.a stralloc.a alloc.a substdio.a error.a \
str.a auto_qmail.o
	./load qreceipt headerbody.o hfield.o quote.o token822.o \
	qmail.o getln.a fd.a wait.a sig.a env.a stralloc.a alloc.a \
	substdio.a error.a str.a auto_qmail.o 

qreceipt.0: \
qreceipt.1
	nroff -man qreceipt.1 > qreceipt.0

qreceipt.o: \
compile qreceipt.c sig.h env.h substdio.h stralloc.h gen_alloc.h \
subfd.h substdio.h getln.h alloc.h str.h hfield.h token822.h \
gen_alloc.h error.h gen_alloc.h gen_allocdefs.h headerbody.h exit.h \
open.h quote.h qmail.h substdio.h
	./compile qreceipt.c

qsmhook: \
load qsmhook.o sig.a case.a fd.a wait.a getopt.a env.a stralloc.a \
alloc.a substdio.a error.a str.a
	./load qsmhook sig.a case.a fd.a wait.a getopt.a env.a \
	stralloc.a alloc.a substdio.a error.a str.a 

qsmhook.o: \
compile qsmhook.c fd.h stralloc.h gen_alloc.h readwrite.h sgetopt.h \
subgetopt.h wait.h env.h byte.h str.h alloc.h exit.h fork.h case.h \
subfd.h substdio.h error.h substdio.h sig.h
	./compile qsmhook.c

qsutil.o: \
compile qsutil.c stralloc.h gen_alloc.h readwrite.h substdio.h \
qsutil.h
	./compile qsutil.c

quote.o: \
compile quote.c stralloc.h gen_alloc.h str.h quote.h
	./compile quote.c

rbl.o: \
compile rbl.c dns.h env.h ipalloc.h qmail.h rbl.h stralloc.h
	./compile rbl.c

rcpthosts.o: \
compile rcpthosts.c cdb.h uint32.h byte.h open.h error.h control.h \
constmap.h stralloc.h gen_alloc.h rcpthosts.h
	./compile rcpthosts.c

readsubdir.o: \
compile readsubdir.c readsubdir.h direntry.h fmt.h scan.h str.h \
auto_split.h
	./compile readsubdir.c

readwrite.o: \
compile readwrite.c readwrite.h
	./compile readwrite.c

read-ctrl.o: \
compile read-ctrl.c auto_qmail.h error.h open.h read-ctrl.h
	./compile read-ctrl.c

received.o: \
compile received.c fmt.h qmail.h substdio.h now.h datetime.h \
datetime.h date822fmt.h received.h
	./compile received.c

remoteinfo.o: \
compile remoteinfo.c byte.h substdio.h ip.h fmt.h timeoutconn.h \
timeoutread.h timeoutwrite.h remoteinfo.h
	./compile remoteinfo.c

scan_8long.o: \
compile scan_8long.c scan.h
	./compile scan_8long.c

scan_ulong.o: \
compile scan_ulong.c scan.h
	./compile scan_ulong.c

seek.a: \
makelib seek_cur.o seek_end.o seek_set.o seek_trunc.o
	./makelib seek.a seek_cur.o seek_end.o seek_set.o \
	seek_trunc.o

seek_cur.o: \
compile seek_cur.c seek.h
	./compile seek_cur.c

seek_end.o: \
compile seek_end.c seek.h
	./compile seek_end.c

seek_set.o: \
compile seek_set.c seek.h
	./compile seek_set.c

seek_trunc.o: \
compile seek_trunc.c seek.h
	./compile seek_trunc.c

select.h: \
compile trysysel.c select.h1 select.h2
	( ./compile trysysel.c >/dev/null 2>&1 \
	&& cat select.h2 || cat select.h1 ) > select.h
	rm -f trysysel.o trysysel

sendmail: \
load sendmail.o env.a getopt.a alloc.a substdio.a error.a str.a \
auto_qmail.o
	./load sendmail env.a getopt.a alloc.a substdio.a error.a \
	str.a auto_qmail.o 

sendmail.o: \
compile sendmail.c sgetopt.h subgetopt.h substdio.h subfd.h \
substdio.h alloc.h auto_qmail.h exit.h env.h str.h
	./compile sendmail.c

setup: \
it man ldap
	./install

sgetopt.o: \
compile sgetopt.c substdio.h subfd.h substdio.h sgetopt.h subgetopt.h \
subgetopt.h
	./compile sgetopt.c

shar: \
FILES BLURB BLURB2 BLURB3 BLURB4 README FAQ INSTALL INSTALL.alias \
INSTALL.ctl INSTALL.ids INSTALL.maildir INSTALL.mbox INSTALL.vsm \
REMOVE.sendmail REMOVE.binmail TEST.deliver TEST.receive UPGRADE \
THOUGHTS TODO THANKS CHANGES SECURITY INTERNALS SENDMAIL \
PIC.local2alias PIC.local2ext PIC.local2local PIC.local2rem \
PIC.local2virt PIC.nullclient PIC.relaybad PIC.relaygood \
PIC.rem2local FILES VERSION SYSDEPS TARGETS Makefile BIN.README \
BIN.Makefile BIN.setup idedit.c conf-break auto_break.h conf-spawn \
auto_spawn.h chkspawn.c conf-split auto_split.h conf-patrn \
auto_patrn.h conf-users conf-groups auto_uids.h auto_usera.h extra.h \
addresses.5 except.1 bouncesaying.1 condredirect.1 dot-qmail.9 \
envelopes.5 forgeries.7 forward.1 maildir2mbox.1 maildirmake.1 \
maildirwatch.1 mailsubj.1 mbox.5 preline.1 qbiff.1 qmail-clean.8 \
qmail-command.8 qmail-control.9 qmail-getpw.9 qmail-header.5 \
qmail-inject.8 qmail-limits.9 qmail-local.8 qmail-log.5 \
qmail-lspawn.8 qmail-newmrh.9 qmail-newu.9 qmail-pop3d.8 \
qmail-popup.8 qmail-pw2u.9 qmail-qmqpc.8 qmail-qmqpd.8 qmail-qmtpd.8 \
qmail-qread.8 qmail-qstat.8 qmail-queue.8 qmail-remote.8 \
qmail-rspawn.8 qmail-send.9 qmail-showctl.8 qmail-smtpd.8 \
qmail-start.9 qmail-tcpok.8 qmail-tcpto.8 qmail-users.9 qmail.7 \
qreceipt.1 splogger.8 tcp-env.1 config.sh config-fast.sh \
qmail-clean.c qmail-getpw.c qmail-inject.c qmail-local.c \
qmail-lspawn.c qmail-newmrh.c qmail-newu.c qmail-pop3d.c \
qmail-popup.c qmail-pw2u.c qmail-qmqpc.c qmail-qmqpd.c qmail-qmtpd.c \
qmail-qread.c qmail-qstat.sh qmail-queue.c qmail-remote.c \
qmail-rspawn.c qmail-send.c qmail-showctl.c qmail-smtpd.c \
qmail-start.c qmail-tcpok.c qmail-tcpto.c spawn.c dnscname.c dnsfq.c \
dnsip.c dnsmxip.c dnsptr.c hostname.c ipmeprint.c tcp-env.c \
sendmail.c qreceipt.c qsmhook.c qbiff.c forward.c preline.c predate.c \
except.c bouncesaying.c condredirect.c maildirmake.c maildir2mbox.c \
maildirwatch.c splogger.c qail.sh elq.sh pinq.sh qmail-upq.sh \
datemail.sh mailsubj.sh qlx.h rcpthosts.h rcpthosts.c commands.h \
commands.c dnsdoe.h dnsdoe.c fmtqfn.h fmtqfn.c gfrom.h gfrom.c \
myctime.h myctime.c newfield.h newfield.c qsutil.h qsutil.c \
readsubdir.h readsubdir.c received.h received.c tcpto.h tcpto.c \
tcpto_clean.c trigger.h trigger.c triggerpull.h triggerpull.c \
trynpbg1.c trysyslog.c conf-cc conf-ld home.sh home+df.sh proc.sh \
proc+df.sh binm1.sh binm2.sh binm3.sh binm1+df.sh binm2+df.sh \
binm3+df.sh find-systype.sh make-compile.sh make-load.sh \
make-makelib.sh trycpp.c warn-auto.sh auto-str.c auto-int.c \
auto-int8.c auto-gid.c auto-uid.c hier.c install.c instcheck.c \
install-big.c alloc.3 alloc.h alloc.c alloc_re.c case.3 case.h \
case_diffb.c case_diffs.c case_lowerb.c case_lowers.c case_starts.c \
cdb.3 cdb.c cdb.h cdb_hash.c cdb_make.c cdb_make.h coe.3 coe.h \
coe.c fd.h fd_copy.3 fd_copy.c fd_move.3 fd_move.c fifo_make.3 \
fifo.h fifo.c trymkffo.c fork.h1 fork.h2 tryvfork.c now.3 now.h now.c \
open.h open_append.c open_excl.c open_read.c open_trunc.c \
open_write.c seek.h seek_cur.c seek_end.c seek_set.c seek_trunc.c \
conf-qmail auto_qmail.h qmail.h qmail.c gen_alloc.h gen_allocdefs.h \
stralloc.3 stralloc.h stralloc_eady.c stralloc_pend.c stralloc_copy.c \
stralloc_opyb.c stralloc_opys.c stralloc_cat.c stralloc_catb.c \
stralloc_cats.c stralloc_arts.c strerr.h strerr_sys.c strerr_die.c \
substdio.h substdio.c substdi.c substdo.c substdio_copy.c subfd.h \
subfderr.c subfdouts.c subfdout.c subfdins.c subfdin.c readwrite.h \
exit.h timeoutconn.h timeoutconn.c timeoutread.h timeoutread.c \
timeoutwrite.h timeoutwrite.c remoteinfo.h remoteinfo.c uint32.h1 \
uint32.h2 tryulong32.c wait.3 wait.h wait_pid.c wait_nohang.c \
trywaitp.c sig.h sig_alarm.c sig_block.c sig_catch.c sig_pause.c \
sig_pipe.c sig_child.c sig_term.c sig_hup.c sig_misc.c sig_bug.c \
trysgact.c trysgprm.c env.3 env.h env.c envread.c byte.h byte_chr.c \
byte_copy.c byte_cr.c byte_diff.c byte_rchr.c byte_zero.c str.h \
str_chr.c str_cpy.c str_diff.c str_diffn.c str_len.c str_rchr.c \
str_start.c lock.h lock_ex.c lock_exnb.c lock_un.c tryflock.c getln.3 \
getln.h getln.c getln2.3 getln2.c sgetopt.3 sgetopt.h sgetopt.c \
subgetopt.3 subgetopt.h subgetopt.c error.3 error_str.3 error_temp.3 \
error.h error.c error_str.c error_temp.c fmt.h fmt_str.c fmt_strn.c \
fmt_uint.c fmt_uint0.c fmt_ulong.c scan.h scan_ulong.c scan_8long.c \
slurpclose.h slurpclose.c quote.h quote.c hfield.h hfield.c \
headerbody.h headerbody.c token822.h token822.c control.h control.c \
datetime.3 datetime.h datetime.c datetime_un.c prioq.h prioq.c \
date822fmt.h date822fmt.c dns.h dns.c trylsock.c tryrsolv.c ip.h ip.c \
ipalloc.h ipalloc.c select.h1 select.h2 trysysel.c ndelay.h ndelay.c \
ndelay_off.c direntry.3 direntry.h1 direntry.h2 trydrent.c prot.h \
prot.c chkshsgr.c warn-shsgr tryshsgr.c ipme.h ipme.c trysalen.c \
maildir.5 maildir.h maildir.c tcp-environ.5 constmap.h constmap.c
	shar -m `cat FILES` > shar
	chmod 400 shar

sig.a: \
makelib sig_alarm.o sig_block.o sig_catch.o sig_pause.o sig_pipe.o \
sig_child.o sig_hup.o sig_term.o sig_bug.o sig_misc.o
	./makelib sig.a sig_alarm.o sig_block.o sig_catch.o \
	sig_pause.o sig_pipe.o sig_child.o sig_hup.o sig_term.o \
	sig_bug.o sig_misc.o

sig_alarm.o: \
compile sig_alarm.c sig.h
	./compile sig_alarm.c

sig_block.o: \
compile sig_block.c sig.h hassgprm.h
	./compile sig_block.c

sig_bug.o: \
compile sig_bug.c sig.h
	./compile sig_bug.c

sig_catch.o: \
compile sig_catch.c sig.h hassgact.h
	./compile sig_catch.c

sig_child.o: \
compile sig_child.c sig.h
	./compile sig_child.c

sig_hup.o: \
compile sig_hup.c sig.h
	./compile sig_hup.c

sig_misc.o: \
compile sig_misc.c sig.h
	./compile sig_misc.c

sig_pause.o: \
compile sig_pause.c sig.h hassgprm.h
	./compile sig_pause.c

sig_pipe.o: \
compile sig_pipe.c sig.h
	./compile sig_pipe.c

sig_term.o: \
compile sig_term.c sig.h
	./compile sig_term.c

slurpclose.o: \
compile slurpclose.c stralloc.h gen_alloc.h readwrite.h slurpclose.h \
error.h
	./compile slurpclose.c

smtpcall.o: \
compile smtpcall.c auto_qmail.h coe.h fd.h substdio.h str.h stralloc.h \
timeoutread.h timeoutwrite.h wait.h smtpcall.h
	./compile smtpcall.c

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

spawn.o: \
compile chkspawn spawn.c sig.h wait.h substdio.h byte.h str.h \
stralloc.h gen_alloc.h select.h exit.h coe.h open.h error.h \
auto_qmail.h auto_uids.h auto_spawn.h
	./chkspawn
	./compile $(DEBUG) spawn.c

splogger: \
load splogger.o substdio.a error.a str.a fs.a syslog.lib socket.lib
	./load splogger substdio.a error.a str.a fs.a  `cat \
	syslog.lib` `cat socket.lib`

splogger.0: \
splogger.8
	nroff -man splogger.8 > splogger.0

splogger.o: \
compile splogger.c error.h substdio.h subfd.h substdio.h exit.h str.h \
scan.h fmt.h
	./compile splogger.c

str.a: \
makelib str_len.o str_diff.o str_diffn.o str_cpy.o str_chr.o \
str_rchr.o str_start.o byte_chr.o byte_rchr.o byte_diff.o byte_copy.o \
byte_cr.o byte_zero.o byte_repl.o
	./makelib str.a str_len.o str_diff.o str_diffn.o str_cpy.o \
	str_chr.o str_rchr.o str_start.o byte_chr.o byte_rchr.o \
	byte_diff.o byte_copy.o byte_cr.o byte_zero.o byte_repl.o

str_chr.o: \
compile str_chr.c str.h
	./compile str_chr.c

str_cpy.o: \
compile str_cpy.c str.h
	./compile str_cpy.c

str_diff.o: \
compile str_diff.c str.h
	./compile str_diff.c

str_diffn.o: \
compile str_diffn.c str.h
	./compile str_diffn.c

str_len.o: \
compile str_len.c str.h
	./compile str_len.c

str_rchr.o: \
compile str_rchr.c str.h
	./compile str_rchr.c

str_start.o: \
compile str_start.c str.h
	./compile str_start.c

stralloc.a: \
makelib stralloc_eady.o stralloc_pend.o stralloc_copy.o \
stralloc_opys.o stralloc_opyb.o stralloc_cat.o stralloc_cats.o \
stralloc_catb.o stralloc_arts.o
	./makelib stralloc.a stralloc_eady.o stralloc_pend.o \
	stralloc_copy.o stralloc_opys.o stralloc_opyb.o \
	stralloc_cat.o stralloc_cats.o stralloc_catb.o \
	stralloc_arts.o

stralloc_arts.o: \
compile stralloc_arts.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_arts.c

stralloc_cat.o: \
compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: \
compile stralloc_catb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_catb.c

stralloc_cats.o: \
compile stralloc_cats.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: \
compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: \
compile stralloc_eady.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_eady.c

stralloc_opyb.o: \
compile stralloc_opyb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_opyb.c

stralloc_opys.o: \
compile stralloc_opys.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: \
compile stralloc_pend.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_pend.c

strerr.a: \
makelib strerr_sys.o strerr_die.o
	./makelib strerr.a strerr_sys.o strerr_die.o

strerr_die.o: \
compile strerr_die.c substdio.h subfd.h substdio.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: \
compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

subfderr.o: \
compile subfderr.c readwrite.h substdio.h subfd.h substdio.h
	./compile subfderr.c

subfdin.o: \
compile subfdin.c readwrite.h substdio.h subfd.h substdio.h
	./compile subfdin.c

subfdins.o: \
compile subfdins.c readwrite.h substdio.h subfd.h substdio.h
	./compile subfdins.c

subfdout.o: \
compile subfdout.c readwrite.h substdio.h subfd.h substdio.h
	./compile subfdout.c

subfdouts.o: \
compile subfdouts.c readwrite.h substdio.h subfd.h substdio.h
	./compile subfdouts.c

subgetopt.o: \
compile subgetopt.c subgetopt.h
	./compile subgetopt.c

substdi.o: \
compile substdi.c substdio.h byte.h error.h
	./compile substdi.c

substdio.a: \
makelib substdio.o substdi.o substdo.o subfderr.o subfdout.o \
subfdouts.o subfdin.o subfdins.o substdio_copy.o readwrite.o
	./makelib substdio.a substdio.o substdi.o substdo.o \
	subfderr.o subfdout.o subfdouts.o subfdin.o subfdins.o \
	substdio_copy.o readwrite.o

substdio.o: \
compile substdio.c substdio.h
	./compile substdio.c

substdio_copy.o: \
compile substdio_copy.c substdio.h
	./compile substdio_copy.c

substdo.o: \
compile substdo.c substdio.h str.h byte.h error.h
	./compile substdo.c

syslog.lib: \
trysyslog.c compile load
	( ( ./compile trysyslog.c && \
	./load trysyslog -lgen ) >/dev/null 2>&1 \
	&& echo -lgen || exit 0 ) > syslog.lib
	rm -f trysyslog.o trysyslog

systype: \
find-systype trycpp.c
	./find-systype > systype

tcp-env: \
load tcp-env.o dns.o remoteinfo.o timeoutread.o timeoutwrite.o \
timeoutconn.o ip.o ipalloc.o case.a ndelay.a sig.a env.a getopt.a \
stralloc.a alloc.a substdio.a error.a str.a fs.a dns.lib socket.lib
	./load tcp-env dns.o remoteinfo.o timeoutread.o \
	timeoutwrite.o timeoutconn.o ip.o ipalloc.o case.a ndelay.a \
	sig.a env.a getopt.a stralloc.a alloc.a substdio.a error.a \
	str.a fs.a  `cat dns.lib` `cat socket.lib`

tcp-env.0: \
tcp-env.1
	nroff -man tcp-env.1 > tcp-env.0

tcp-env.o: \
compile tcp-env.c sig.h stralloc.h gen_alloc.h str.h env.h fmt.h \
scan.h subgetopt.h ip.h dns.h byte.h remoteinfo.h exit.h case.h
	./compile tcp-env.c

tcp-environ.0: \
tcp-environ.5
	nroff -man tcp-environ.5 > tcp-environ.0

tcpto.o: \
compile tcpto.c tcpto.h open.h lock.h seek.h now.h datetime.h ip.h \
byte.h datetime.h readwrite.h
	./compile tcpto.c

tcpto_clean.o: \
compile tcpto_clean.c tcpto.h open.h substdio.h readwrite.h
	./compile tcpto_clean.c

timeoutconn.o: \
compile timeoutconn.c ndelay.h select.h error.h readwrite.h ip.h \
byte.h timeoutconn.h
	./compile timeoutconn.c

timeoutread.o: \
compile timeoutread.c timeoutread.h select.h error.h readwrite.h
	./compile timeoutread.c

timeoutwrite.o: \
compile timeoutwrite.c timeoutwrite.h select.h error.h readwrite.h
	./compile timeoutwrite.c

token822.o: \
compile token822.c stralloc.h gen_alloc.h alloc.h str.h token822.h \
gen_alloc.h gen_allocdefs.h
	./compile token822.c

trigger.o: \
compile trigger.c select.h open.h trigger.h hasnpbg1.h
	./compile trigger.c

triggerpull.o: \
compile triggerpull.c ndelay.h open.h triggerpull.h
	./compile triggerpull.c

uint32.h: \
tryulong32.c compile load uint32.h1 uint32.h2
	( ( ./compile tryulong32.c && ./load tryulong32 && \
	./tryulong32 ) >/dev/null 2>&1 \
	&& cat uint32.h2 || cat uint32.h1 ) > uint32.h
	rm -f tryulong32.o tryulong32

wait.a: \
makelib wait_pid.o wait_nohang.o
	./makelib wait.a wait_pid.o wait_nohang.o

wait_nohang.o: \
compile wait_nohang.c haswaitp.h
	./compile wait_nohang.c

wait_pid.o: \
compile wait_pid.c error.h haswaitp.h
	./compile wait_pid.c

xtext.o: \
compile xtext.c xtext.h stralloc.h
	./compile xtext.c

cert:
	$(OPENSSLBIN) req -new -x509 -nodes \
	-out `head -1 conf-qmail`/control/cert.pem -days 366 \
	-keyout `head -1 conf-qmail`/control/cert.pem
	chmod 640 `head -1 conf-qmail`/control/cert.pem
	chown qmaild:qmail `head -1 conf-qmail`/control/cert.pem

cert-req:
	$(OPENSSLBIN) req -new -nodes \
	-out req.pem \
	-keyout `head -1 conf-qmail`/control/cert.pem
	chmod 640 `head -1 conf-qmail`/control/cert.pem
	chown qmaild:qmail `head -1 conf-qmail`/control/cert.pem
	@echo
	@echo "Send req.pem to your CA to obtain signed_req.pem, and do:"
	@echo "cat signed_req.pem >> `head -1 conf-qmail`/control/cert.pem"

backup: \
clean
	tar cf $(BACKUPPATH) .
