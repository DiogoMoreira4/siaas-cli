#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

BACKUP_OWNER="`loginctl user-status | head -1 | awk '{print $1}'`"
bak_user=`id -u "${BACKUP_OWNER}"`
bak_group=`id -g "${BACKUP_OWNER}"`
now=`date +%Y%m%d%H%M%S`

cd ${SCRIPT_DIR}
./venv/bin/pip3 freeze > ./requirements.txt
chmod 664 ./requirements.txt
rm -rf ./__pycache__
rm -rf ./log
rm -rf ./tmp
rm -rf ./var
sudo chown -R ${bak_user}:${bak_group} .

cd ..
tar --exclude='siaas-cli/venv' --exclude='siaas-cli/.git*' -cpzf ./siaas-cli-${now}.tgz siaas-cli
chown ${bak_user}:${bak_group} siaas-cli-${now}.tgz
chmod 664 siaas-cli-${now}.tgz

stat siaas-cli-${now}.tgz
