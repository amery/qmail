#!/bin/sh
exec 2>&1
#
# qmail-send and friends
#
QMAIL="%QMAIL%"
if [ -e $QMAIL/control/defaultdelivery ]; then
	ALIASEMPTY=`cat $QMAIL/control/defaultdelivery 2> /dev/null`
else
	ALIASEMPTY=`cat $QMAIL/control/aliasempty 2> /dev/null`
fi
ALIASEMPTY=${ALIASEMPTY:="./Maildir/"}

PATH="$QMAIL/bin:$PATH"

# limit to prevent memory hogs
ulimit -c 204800 

exec envdir ./env qmail-start "$ALIASEMPTY"

