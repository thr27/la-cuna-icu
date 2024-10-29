#!/bin/bash
set -x
SCRIPT=`readlink -f -- $0`
SCRIPTPATH=`dirname $SCRIPT`

SERVERNAME=server1
DOMAIN=prd.vagrant

[ ! -f $SCRIPTPATH/bootstrap.sh ] && wget -O $SCRIPTPATH/bootstrap.sh https://thr27.github.io/la-cuna-icu/bootstrap.sh 

if [ -f $SCRIPTPATH/bootstrap.sh ]; then
    chmod +x $SCRIPTPATH/bootstrap.sh
    source $SCRIPTPATH/bootstrap.sh
else
    echo "Error: bootstrap.sh not found"
fi
