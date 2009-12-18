#!/bin/sh
exec 2>&1
#
# pop before smtp database daemon
#
QMAIL="%QMAIL%"
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
	setuidgid $QUSER \
	$QMAIL/bin/pbsdbd

