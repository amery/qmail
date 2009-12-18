#!/bin/sh
exec 2>&1
#
# QMQP service 
#
QMAIL="%QMAIL%"
ME="`head -1 $QMAIL/control/me`"
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

exec \
	envuidgid $QUSER \
	tcpserver -v -URl $ME -x$QMAIL/control/qmail-qmqpd.cdb \
	    ${CONCURRENCY:+"-c$CONCURRENCY"} ${BACKLOG:+"-b$BACKLOG"} 0 628 \
	$QMAIL/bin/qmail-qmqpd

