# siaas-cli

_Intelligent System for Automation of Security Audits (SIAAS) - Command Line Interface_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD), 2023

__

**Instructions (tested on Ubuntu 20.04 "Focal")**

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

API info, but limit the number of chars per line to adapt readibility: `siaas-cli api-show -L 100`

- Server:

Show server information and currently active configurations: `siaas-cli server-show`

Publish server configuration key(s) (configure email and report type): `siaas-cli server-configs-add-or-update mailer_smtp_account=john.smith@gmail.com,mailer_smtp_pwd=Password123,mailer_smtp_server=smtp.gmail.com,mailer_smtp_tls_port=587,mailer_smtp_receivers=joanna.smith@nowhere.com,mailer_smtp_report_type=vuln_only`

Show published configuration keys for the server: `siaas-cli server-configs-show`

Remove published server configuration key 'mailer_smtp_receivers': `siaas-cli server-configs-remove mailer_smtp_receivers`

Clear all published server configuration keys (restores config from server's local config file): `siaas-cli server-configs-clear`

- Agents:

Show active agents and their last ping: `siaas-cli agents-show`

Show all metrics from all agents (usually this is too much data to read by the human eye): `siaas-cli agents-data-show`

Show the neighborhood of all agents: `siaas-cli agents-data-show -m neighborhood`

Show the active configuration for an agent (defaults to local config file if no configs are published for a said key): `siaas-cli agents-data-show -m config 10000000dbb5bbc1`

Publish configuration key(s) for an agent (configure hosts to scan and nmap scripts to run): `siaas-cli agents-configs-add-or-update 10000000dbb5bbc1 manual_hosts=\"google.com,microsoft.com\",nmap_scripts=\"vuln,vulscan\"`

Show published configuration keys for an agent: `siaas-cli agents-configs-show 10000000dbb5bbc1`

Remove published key 'nmap_scripts' for two agents (go back to using local config file): `siaas-cli agents-configs-remove 10000000dbb5bbc1,0924aa8b-6dc9-4fec-9716-d1601fc8b6c6 nmap_scripts`

Clear all published configuration keys for an agent (restores config from agent's local config file): `siaas-cli agents-configs-clear 10000000dbb5bbc1`

Force this config to be empty (override local config): `siaas-cli agents-configs-add-or-update 10000000dbb5bbc1 nmap_scripts=\"\"`

- Agents (Broadcast):

Show published configurations for all agents (published single-agent configurations, if existing, will always take precedence): `siaas-cli agents-configs-broadcast-show`

Publish configuration key(s) for all agents (configure portscanner loop interval to once a day): `siaas-cli agents-configs-broadcast-add-or-update portscanner_loop_interval_sec=86400`

Show published configuration keys for all agents: `siaas-cli agents-configs-broadcast-show`

Remove published key 'portscanner_loop_interval' for all agents: `siaas-cli agents-configs-broadcast-remove portscanner_loop_interval`

Clear all published configuration keys for all agents (restores config from agents' local config files): `siaas-cli agents-configs-broadcast-clear`

- Vulnerability Report:

Show vulnerabilities found in host '192.168.122.1': `siaas-cli vuln-report -r vuln_only -t 192.168.122.1`
