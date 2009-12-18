#!/bin/sh
exec 2>&1
#
# IMAP service: this script is for courier-imap
#
QMAIL="%QMAIL%"
ME="`head -1 $QMAIL/control/me`"
if [ -e $QMAIL/control/defaultdelivery ]; then
        ALIASEMPTY=`head -1 $QMAIL/control/defaultdelivery 2> /dev/null`
else
        ALIASEMPTY=`head -1 $QMAIL/control/aliasempty 2> /dev/null`
fi
ALIASEMPTY=${ALIASEMPTY:="./Maildir/"}

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - PATH=$PATH envdir ./env awk '\
	BEGIN { for (i in ENVIRON) \
		if (i != "PATH") { \
			printf "export %s=\"%s\"\\n", i, ENVIRON[i] \
		} \
	}'`

# enforce some sane defaults
COURIER=${COURIER:="/usr/local"}
TLSCERT=${TLSCERT:="$QMAIL/control/cert.pem"}
PBSTOOL=${PBSTOOL:="$QMAIL/bin/pbsadd"}

if [ X${NOPBS+"true"} = X"true" ]; then
	unset PBSTOOL
fi

exec \
	tcpserver -v -HRl $ME -x$QMAIL/control/qmail-imapd.cdb \
	    ${CONCURRENCY:+"-c$CONCURRENCY"} ${BACKLOG:+"-b$BACKLOG"} \
	    -s ${TLSCERT:+"-n$TLSCERT"} 0 imaps \
	$COURIER/sbin/imaplogin \
	$QMAIL/bin/auth_imap ${PBSTOOL:+"-d$PBSTOOL"}\
	$COURIER/bin/imapd "$ALIASEMPTY"
