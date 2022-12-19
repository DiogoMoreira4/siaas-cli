# siaas-cli

_Intelligent System for Automation of Security Audits (SIAAS) - Command Line Interface_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD).

__

**Instructions (tested on Ubuntu 20.04 "Focal")**

 - Install and configure: `sudo ./siaas_cli_install_and_configure.sh`

 - Usage:

`source ./siaas_env`
`siaas-cli` or `./siaas_cli_run.sh`

 - Logs: `tail -100f ./log/siaas-cli.log`

 - Generate a project archive (it is recommended to stop all processes before): `sudo ./siaas_cli_archive.sh`

 - Remove: `sudo ./siaas_cli_remove.sh`
