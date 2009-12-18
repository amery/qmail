#!/bin/sh
exec 2>&1
#
# SMTP service 
#
QMAIL="%QMAIL%"
ME="`head -1 $QMAIL/control/me`"
CONCURRENCY=${CONCURRENCY:=50}
QUSER="qmaild"

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - PATH=$PATH envdir ./env awk '\
	BEGIN { for (i in ENVIRON) \
		if (i != "PATH") { \
			printf "export %s=\"%s\"\\n", i, ENVIRON[i] \
		} \
	}'`

# enforce some sane defaults
QUSER=${QUSER:="qmaild"}
PBSTOOL=${PBSTOOL:="$QMAIL/bin/pbscheck"}

if [ X${NOPBS+"true"} = X"true" ]; then
	unset PBSTOOL
fi

exec \
	envuidgid $QUSER \
	tcpserver -v -URl $ME -x$QMAIL/control/qmail-smtpd.cdb \
	    ${CONCURRENCY:+"-c$CONCURRENCY"} ${BACKLOG:+"-b$BACKLOG"} 0 smtp \
	$PBSTOOL \
	$QMAIL/bin/qmail-smtpd

