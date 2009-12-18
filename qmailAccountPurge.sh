#!/bin/sh

case "$1" in

show)

        /usr/local/bin/ldapsearch \
        -u -F "=" \
        -h "`cat /var/qmail/control/ldapserver`" \
        -b "`cat /var/qmail/control/ldapbasedn`" \
        -S "mail" \
        "(&(accountStatus=deleted)(qmailAccountPurge=<`/var/qmail/bin/gettimeofday`))" \
        mail mailAlternateAddress uid mailMessageStore mailHost

        ;;

purge)

	;;

esac

