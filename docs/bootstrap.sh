#!/bin/bash
set -x
echo $0
SCRIPT=`readlink -f -- $0`
SCRIPTPATH=`dirname $SCRIPT`

if [ "$EUID" -ne 0 ]
	then echo "Please run as root"
	exit -1
fi
FQDN=${SERVERNAME}.${DOMAIN}
SERVER_IP=$(echo $SSH_CONNECTION | cut -d ' ' -f 3)

if ! fgrep -q ${SERVER_IP} /etc/hosts ; then
    echo Adding $SERVER_IP $FQDN to /etc/hosts
    echo $SERVER_IP ${FQDN} ${SERVERNAME} >> /etc/hosts
fi

if [ ! $(hostname -f)  != "$FQDN" ]; then
    echo Setting hostname to $SERVERNAME
    echo ${SERVERNAME} > /etc/hostname

    hostnamectl set-hostname ${FQDN}
fi

[ ! -f $SCRIPTPATH/salt.sh ] && wget -O $SCRIPTPATH/salt.sh https://thr27.github.io/la-cuna-icu/scripts/salt.sh
[ -f $SCRIPTPATH/salt.sh ] && chmod +x $SCRIPTPATH/salt.sh