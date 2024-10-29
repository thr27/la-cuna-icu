#!bin/bash

SERVERNAME=server1
DOMAIN=la-cuna.icu

wget https://thr27.github.io/la-cuna-icu/bootstrap.sh
if [ -f ./bootstrap.sh ]; then
  chmod +x bootstrap.sh
./bootstrap.sh
else
  echo "Error: bootstrap.sh not found"
fi
