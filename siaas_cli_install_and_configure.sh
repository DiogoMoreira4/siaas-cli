#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

cd ${SCRIPT_DIR}

# INSTALL PACKAGES
apt-get update
apt-get install -y python3 python3-pip python3-venv git ca-certificates || exit 1

# SERVICE CONFIGURATION
ln -fs ${SCRIPT_DIR}/siaas_cli_run.sh /usr/local/bin/siaas-cli
#ln -fs ${SCRIPT_DIR}/log /var/log/siaas-cli

# INITIALIZE
sudo rm -rf ${SCRIPT_DIR}/venv
${SCRIPT_DIR}/siaas_cli_venv_setup.sh

echo -e "\nSIAAS CLI is installed. To use it, first edit the credentials file \"siaas_env\" (if needed) and then source it with the command \"source siaas_env\", and then:\n\n siaas-cli\n"
