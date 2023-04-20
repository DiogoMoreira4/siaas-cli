# siaas-cli

_Intelligent System for Automation of Security Audits (SIAAS) - Command Line Interface_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD), 2023

__

**Instructions (tested on Ubuntu 20.04 "Focal", Ubuntu 22.04 "Jammy", and Debian 11 "Bullseye")**

 - Install and configure: `sudo ./siaas_cli_install_and_configure.sh`

 - Usage:

1. Edit and then export the credentials file: `source ./siaas_env`
2. Run the CLI: `siaas-cli` or `./siaas_cli_run.sh`

 - Logs: `tail -100f ./log/siaas-cli.log`

 - Generate a project archive (it is recommended to stop all processes before): `sudo ./siaas_cli_archive.sh`

 - Remove: `sudo ./siaas_cli_remove.sh`

__

**Examples**

- API:

API info: `siaas-cli api-show`

API info, but change the number of indentation spaces to adapt readibility: `siaas-cli api-show -S 2`

API info, but with a colorful output: `siaas-cli api-show -C`

API info, but with no SSL CA verification: `siaas-cli api-show -I`

- Server:

Show server information and currently active configurations: `siaas-cli server-show`

Publish server configuration key(s) (configure email and report type): `siaas-cli server-configs-add-or-update mailer_smtp_account=john.smith@gmail.com,mailer_smtp_pwd=Password123,mailer_smtp_server=smtp.gmail.com,mailer_smtp_tls_port=587,mailer_smtp_recipients=joanna.smith@nowhere.com,mailer_smtp_report_type=vuln_only`

Show published configuration keys for the server: `siaas-cli server-configs-show`

Remove published server configuration key 'mailer_smtp_recipients' (go back to using local config file or default value for this key): `siaas-cli server-configs-remove mailer_smtp_recipients`

Clear all published server configuration keys (all configurations will reset to the server's local config file or defaults): `siaas-cli server-configs-clear`

- Agents:

Show active agents and their last ping: `siaas-cli agents-show`

Show all metrics from all agents (usually this is too much data to read by the human eye): `siaas-cli agents-data-show`

Show the neighborhood of all agents: `siaas-cli agents-data-show -m neighborhood`

Show the currently active configurations for an agent (keys will show the local config file or defaults if no value is published for them): `siaas-cli agents-data-show -m config 10000000dbb5bbc1`

Publish configuration key(s) for an agent (configure hosts to scan and nmap scripts to run): `siaas-cli agents-configs-add-or-update 10000000dbb5bbc1 manual_hosts='"google.com,microsoft.com"',nmap_scripts='"vuln,vulscan"'`

Configure nickname and description for an agent: `siaas-cli agents-configs-add-or-update 10000000dbb5bbc1 nickname=RPi4,description="A Raspberry Pi 4 agent"`

Show published configuration keys for an agent: `siaas-cli agents-configs-show 10000000dbb5bbc1`

Remove published key 'nmap_scripts' for two agents (go back to using local config file or default value for this key): `siaas-cli agents-configs-remove 10000000dbb5bbc1,0924aa8b-6dc9-4fec-9716-d1601fc8b6c6 nmap_scripts`

Clear all published configuration keys for an agent (all configurations will reset to the agent's local config file or defaults): `siaas-cli agents-configs-clear 10000000dbb5bbc1`

Force a configuration value to be empty (this overrides local config or defaults for this key): `siaas-cli agents-configs-add-or-update 10000000dbb5bbc1 nmap_scripts=""`

- Agents (Broadcast configurations):

Show published broadcast configurations (note: published single-agent configurations, if existing, will always take precedence): `siaas-cli agents-configs-broadcast-show`

Publish broadcast configuration key(s) (configure port scanning loop interval to twice a day, and to transfer data in loops of 2 hours): `siaas-cli agents-configs-broadcast-add-or-update portscanner_loop_interval_sec=43200,datatransfer_loop_interval_sec=7200`

Show published broadcast configuration keys: `siaas-cli agents-configs-broadcast-show`

Remove published broadcast key 'portscanner_loop_interval_sec': `siaas-cli agents-configs-broadcast-remove portscanner_loop_interval_sec`

Clear all published broadcast configuration keys: `siaas-cli agents-configs-broadcast-clear`

- Vulnerability Report:

Show only exploitable vulnerabilities found in host '192.168.122.1': `siaas-cli vuln-report -r exploit_vuln_only -t 192.168.122.1`
