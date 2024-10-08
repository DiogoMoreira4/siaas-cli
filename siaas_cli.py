# Intelligent System for Automation of Security Audits (SIAAS)
# Command Line Interface
# By João Pedro Seara, 2022-2024

import click
import requests
import urllib3
import pprint
import json
import logging
import re
import sys
from pygments import highlight, lexers, formatters

logger = logging.getLogger(__name__)

SIAAS_VERSION = "1.0.1"

_cmd_options = [
    click.option('-A', '--api', help="SIAAS API URI. (Default: https://127.0.0.1/api)",
                 envvar='SIAAS_API_URI', default="https://127.0.0.1/api"),
    click.option('-U', '--user', help="SIAAS API user.",
                 envvar='SIAAS_API_USER'),
    click.option('-P', '--password', help="SIAAS API password.",
                 envvar='SIAAS_API_PWD'),
    click.option('-B', '--ca-bundle', help="SIAAS SSL CA bundle path.",
                 envvar='SIAAS_API_SSL_CA_BUNDLE'),
    click.option('-I', '--insecure', is_flag=True,
                 help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY'),
    click.option('-T', '--timeout', help="SIAAS API timeout. (Default: 60)",
                 envvar='SIAAS_API_TIMEOUT', default=60),
    click.option('-D', '--debug', is_flag=True,
                 help="Enable debug logs.", envvar='SIAAS_DEBUG_LOGS'),
    click.option('-C', '--colors', is_flag=True,
                 help="Enable colors in the output.", envvar='SIAAS_OUTPUT_COLORS'),
    click.option('-S', '--indent-spaces', help="Number of indentation spaces per level in the output. (Default: 4)",
                 envvar='SIAAS_OUTPUT_INDENT_SPACES', default=4)
]


def add_options(options):
    """
    Allows reusing the received list of CLI options, in different functions
    """
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func
    return _add_options


def print_pretty_output(out_dict, indent=4, colors=False):
    """
    Receives an output dict and prints it in a pretty JSON format
    Allows the number of indentation spaces to be changed, and to toggle output colorization
    Will always disable colors if the output is being redirected
    """
    output_json = json.dumps(out_dict, indent=indent,
                             sort_keys=False, ensure_ascii=False)
    if colors and sys.stdout.isatty():  # only colorize json if the output is the terminal
        output_json = highlight(
            output_json, lexers.JsonLexer(), formatters.TerminalFormatter())
    print(output_json)


def grab_vulns_from_agent_data_dict(agent_data_dict, target_host=None, report_type="vuln_only"):
    """
    Receives an agent data dict and returns a list of vulnerabilities, depending on report_type: 'all', 'vuln_only', 'exploit_vuln_only'
    Returns the vuln dict if all OK; Returns False if anything fails
    """
    if len(report_type or '') == 0:
        report_type = "vuln_only"

    new_dict = {}

    if report_type.lower() == "all":
        try:
            for a in agent_data_dict.keys():
                for b in agent_data_dict[a].keys():
                    if b == "portscanner":
                        for c in agent_data_dict[a][b].keys():
                            if len(target_host or '') > 0 and c not in target_host.split(','):
                                continue
                            if a not in new_dict.keys():
                                new_dict[a] = {}
                            if b not in new_dict[a].keys():
                                new_dict[a][b] = {}
                            new_dict[a][b][c] = agent_data_dict[a][b][c]
        except Exception as e:
            logger.error("Error generating new dict: "+str(e))
            exit(1)
    else:
        try:
            for a in agent_data_dict.keys():
                for b in agent_data_dict[a].keys():
                    if b == "portscanner":
                        for c in agent_data_dict[a][b].keys():
                            if len(target_host or '') > 0 and c not in target_host.split(','):
                                continue
                            for d in agent_data_dict[a][b][c].keys():
                                if d == "last_check":
                                    if a not in new_dict.keys():
                                        new_dict[a] = {}
                                    if b not in new_dict[a].keys():
                                        new_dict[a][b] = {}
                                    if c not in new_dict[a][b].keys():
                                        new_dict[a][b][c] = {}
                                    new_dict[a][b][c]["last_check"] = agent_data_dict[a][b][c]["last_check"]
                                if d == "scanned_ports":
                                    for e in agent_data_dict[a][b][c][d].keys():
                                        for f in agent_data_dict[a][b][c][d][e].keys():
                                            if f == "scan_results":
                                                for g in agent_data_dict[a][b][c][d][e][f].keys():
                                                    for h in agent_data_dict[a][b][c][d][e][f][g].keys():
                                                        if "vulners" in h or "vulscan" in h:
                                                            if report_type.lower() == "exploit_vuln_only":
                                                                for i in agent_data_dict[a][b][c][d][e][f][g][h].keys():
                                                                    for j in agent_data_dict[a][b][c][d][e][f][g][h][i].keys():
                                                                        if "siaas_exploit_tag" in agent_data_dict[a][b][c][d][e][f][g][h][i][j]:
                                                                            if a not in new_dict.keys():
                                                                                new_dict[a] = {
                                                                                }
                                                                            if b not in new_dict[a].keys():
                                                                                new_dict[a][b] = {
                                                                                }
                                                                            if c not in new_dict[a][b].keys():
                                                                                new_dict[a][b][c] = {
                                                                                }
                                                                            if d not in new_dict[a][b][c].keys():
                                                                                new_dict[a][b][c][d] = {
                                                                                }
                                                                            if e not in new_dict[a][b][c][d].keys():
                                                                                new_dict[a][b][c][d][e] = {
                                                                                }
                                                                            if f not in new_dict[a][b][c][d][e].keys():
                                                                                new_dict[a][b][c][d][e][f] = {
                                                                                }
                                                                            if g not in new_dict[a][b][c][d][e][f].keys():
                                                                                new_dict[a][b][c][d][e][f][g] = {
                                                                                }
                                                                            if h not in new_dict[a][b][c][d][e][f][g].keys():
                                                                                new_dict[a][b][c][d][e][f][g][h] = {
                                                                                }
                                                                            if i not in new_dict[a][b][c][d][e][f][g][h].keys():
                                                                                new_dict[a][b][c][d][e][f][g][h][i] = {
                                                                                }
                                                                            new_dict[a][b][c][d][e][f][g][h][i][
                                                                                j] = agent_data_dict[a][b][c][d][e][f][g][h][i][j]
                                                            else:  # default to vuln_only
                                                                if a not in new_dict.keys():
                                                                    new_dict[a] = {
                                                                    }
                                                                if b not in new_dict[a].keys():
                                                                    new_dict[a][b] = {
                                                                    }
                                                                if c not in new_dict[a][b].keys():
                                                                    new_dict[a][b][c] = {
                                                                    }
                                                                if d not in new_dict[a][b][c].keys():
                                                                    new_dict[a][b][c][d] = {
                                                                    }
                                                                if e not in new_dict[a][b][c][d].keys():
                                                                    new_dict[a][b][c][d][e] = {
                                                                    }
                                                                if f not in new_dict[a][b][c][d][e].keys():
                                                                    new_dict[a][b][c][d][e][f] = {
                                                                    }
                                                                if g not in new_dict[a][b][c][d][e][f].keys():
                                                                    new_dict[a][b][c][d][e][f][g] = {
                                                                    }
                                                                new_dict[a][b][c][d][e][f][g][h] = agent_data_dict[a][b][c][d][e][f][g][h]
        except Exception as e:
            logger.error("Error generating new dict: "+str(e))
            exit(1)

    return new_dict


@click.group()
@click.version_option(version=SIAAS_VERSION)
def siaas():
    """
    A CLI wrapper for the SIAAS Server API.
    """


@add_options(_cmd_options)
@siaas.command("api-show")
def api_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Shows API information.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        r = requests.get(api, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these modules (comma-separated).")
@siaas.command("server-show")
def server_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, module: str):
    """
    Shows server information.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server"
        if len(module or '') > 0:
            request_uri += "?module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@siaas.command("server-configs-show")
def server_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Shows published server configuration keys. (WARNING: This command might display passwords in clear text!)
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        r = requests.get(api+"/siaas-server/configs", timeout=timeout,
                         verify=verify, allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@siaas.command("server-configs-add-or-update")
def server_configs_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, key_value: str):
    """
    Adds or updates published server configuration keys (accepts multiple configuration key=value pairs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    delta_config_dict = {}
    current_config_dict = r.json()["output"]
    for kv in re.split(''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', key_value):  # special handling of groups of comma-separated values within quotes
        try:
            config_name = kv.split("=", 1)[0].strip().strip('\'\"').strip()
            config_value = kv.split("=", 1)[1].strip().strip('\'\"').strip()
        except Exception as e:
            logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
            continue
        delta_config_dict[config_name] = config_value
    try:
        new_config_dict = dict(
            list(current_config_dict.items()) + list(delta_config_dict.items()))
        request_uri = api+"/siaas-server/configs"
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                          verify=verify, allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was written to the server API:\n" +
                     pprint.pformat(new_config_dict, sort_dicts=False))
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error posting data to the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@siaas.command("server-configs-remove")
def server_configs_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, key: str):
    """
    Removes published server configuration keys (accepts multiple configuration keys, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    current_config_dict = r.json()["output"]
    new_config_dict = dict(current_config_dict)
    for k in key.split(','):
        config_name = k.strip()
        new_config_dict.pop(config_name, None)
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                          verify=verify, allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was written to the server API:\n" +
                     pprint.pformat(new_config_dict, sort_dicts=False))
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error posting data to the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@siaas.command("server-configs-clear")
def server_configs_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Clears all published server configuration keys.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.delete(request_uri, timeout=timeout, verify=verify,
                            allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error deleting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-s', '--sort', help="Use 'agent' or 'date' to sort. (Default: 'date')", default="date")
@siaas.command("agents-show")
def agents_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, sort: str):
    """
    Shows agent information.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/agents"
        request_uri += "?sort="+sort
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))

    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these modules (comma-separated).")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-data-show")
def agents_data_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, module: str):
    """
    Shows most recent data/metrics from agents (accepts multiple agent UIDs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        if len(agent_uid or '') > 0:
            request_uri = api+"/siaas-server/agents/data/"+agent_uid
        else:
            request_uri = api+"/siaas-server/agents/data"
        if len(module or '') > 0:
            request_uri += "?module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-d', '--days', help="Number of past days to keep. (Default: 15)", default=15)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-data-delete")
def agents_data_delete(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, days: int):
    """
    Deletes agent data (accepts multiple agent UIDs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/agents/data/"+agent_uid
        request_uri += "?days="+str(days)
        r = requests.delete(request_uri, timeout=timeout, verify=verify,
                            allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error deleting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-b', '--broadcast', is_flag=True, help="Merge broadcast configurations.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-configs-show")
def agents_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, broadcast: bool):
    """
    Shows published agent configuration keys (accepts multiple agent UIDs, comma-separated). (WARNING: This command might display passwords in clear text!)
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        if len(agent_uid or '') > 0:
            request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        else:
            request_uri = api+"/siaas-server/agents/configs"
        if broadcast:
            request_uri += "?merge_broadcast=1"
        else:
            request_uri += "?merge_broadcast=0"
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-add-or-update")
def agents_configs_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, key_value: str):
    """
    Adds or updates published agent configuration keys (accepts multiple agent UIDs and also multiple configuration key=value pairs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    result = 0
    for a in agent_uid.split(','):
        current_config_dict = {}
        delta_config_dict = {}
        new_config_dict = {}
        if a in r.json()["output"].keys():
            current_config_dict = r.json()["output"][a]
        for kv in re.split(''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', key_value):  # special handling of groups of comma-separated values within quotes
            try:
                config_name = kv.split("=", 1)[0].strip().strip('\'\"').strip()
                config_value = kv.split(
                    "=", 1)[1].strip().strip('\'\"').strip()
            except Exception as e:
                logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
                continue
            delta_config_dict[config_name] = config_value
        r2 = "N/A"
        try:
            new_config_dict = dict(
                list(current_config_dict.items()) + list(delta_config_dict.items()))
            request_uri = api+"/siaas-server/agents/configs/"+a
            r2 = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                               verify=verify, allow_redirects=True, auth=(user, password))
        except Exception as e:
            logger.error(
                "Error while performing a POST request to the server API: "+str(e))
            result = 1
        if hasattr(r2, "status_code") and r2.status_code == 200:
            logger.debug("All data that was written to the server API:\n" +
                         pprint.pformat(new_config_dict, sort_dicts=False))
            print_pretty_output(r2.json(), indent_spaces, colors)
        else:
            if hasattr(r2, "status_code"):
                exit_code = r2.status_code
            else:
                exit_code = r2
            logger.error(
                "Error posting data to the server API: "+str(exit_code))
            result = 1
    exit(result)


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-remove")
def agents_configs_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, key: str):
    """
    Removes published agent configuration keys (accepts multiple agent UIDs and also multiple configuration keys, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    result = 0
    for a in agent_uid.split(','):
        current_config_dict = {}
        if a in r.json()["output"].keys():
            current_config_dict = r.json()["output"][a]
        new_config_dict = dict(current_config_dict)
        for k in key.split(','):
            config_name = k.strip()
            new_config_dict.pop(config_name, None)
        r2 = "N/A"
        try:
            request_uri = api+"/siaas-server/agents/configs/"+a
            r2 = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                               verify=verify, allow_redirects=True, auth=(user, password))
        except Exception as e:
            logger.error(
                "Error while performing a POST request to the server API: "+str(e))
            result = 1
        if hasattr(r2, "status_code") and r2.status_code == 200:
            logger.debug("All data that was written to the server API:\n" +
                         pprint.pformat(new_config_dict, sort_dicts=False))
            print_pretty_output(r2.json(), indent_spaces, colors)
        else:
            if hasattr(r2, "status_code"):
                exit_code = r2.status_code
            else:
                exit_code = r2
            logger.error(
                "Error posting data to the server API: "+str(exit_code))
            result = 1
    exit(result)


@add_options(_cmd_options)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-clear")
def agents_configs_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str):
    """
    Clears all published agent configuration keys (accepts multiple agent UIDs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.delete(request_uri, timeout=timeout, verify=verify,
                            allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error interacting with the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@siaas.command("agents-configs-broadcast-show")
def agents_configs_broadcast_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Shows published agent broadcast configuration keys. (WARNING: This command might display passwords in clear text!)
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@siaas.command("agents-configs-broadcast-add-or-update")
def agents_configs_broadcast_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, key_value: str):
    """
    Adds or updates published agent broadcast configuration keys (accepts multiple configuration key=value pairs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    current_config_dict = {}
    delta_config_dict = {}
    if agent_uid in r.json()["output"].keys():
        current_config_dict = r.json()["output"][agent_uid]
    for kv in re.split(''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', key_value):  # special handling of groups of comma-separated values within quotes
        try:
            config_name = kv.split("=", 1)[0].strip().strip('\'\"').strip()
            config_value = kv.split("=", 1)[1].strip().strip('\'\"').strip()
        except Exception as e:
            logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
            continue
        delta_config_dict[config_name] = config_value
    try:
        new_config_dict = dict(
            list(current_config_dict.items()) + list(delta_config_dict.items()))
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                          verify=verify, allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was written to the server API:\n" +
                     pprint.pformat(new_config_dict, sort_dicts=False))
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error posting data to the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@siaas.command("agents-configs-broadcast-remove")
def agents_configs_broadcast_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, key: str):
    """
    Removes published agent broadcast configuration keys (accepts multiple configuration keys, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    current_config_dict = {}
    if agent_uid in r.json()["output"].keys():
        current_config_dict = r.json()["output"][agent_uid]
    new_config_dict = dict(current_config_dict)
    for k in key.split(','):
        config_name = k.strip()
        new_config_dict.pop(config_name, None)
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout,
                          verify=verify, allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was written to the server API:\n" +
                     pprint.pformat(new_config_dict, sort_dicts=False))
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error posting data to the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@siaas.command("agents-configs-broadcast-clear")
def agents_configs_broadcast_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Clears all published agent broadcast configuration keys.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.delete(request_uri, timeout=timeout, verify=verify,
                            allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error deleting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these modules (comma-separated).")
@click.option('-l', '--limit', help="Max number of records to show (less than 1 means no limit). (Default: 10)", default=10)
@click.option('-d', '--days', help="Max number of past days to show. (Default: 2)", default=2)
@click.option('-s', '--sort', help="Use 'agent' or 'date' to sort. (Default: 'date')", default="date")
@click.option('-o', '--older', is_flag=True, help="Show older records first.")
@click.option('-h', '--hide', is_flag=True, help="Hide empty entries.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-history-show")
def agents_history_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent_uid: str, module: str, limit: int, days: int, sort: str, older: bool, hide: bool):
    """
    Shows historical data/metrics from agents (accepts multiple agent UIDs, comma-separated).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        if limit < 1:
            logger.warning(
                "No limit is set. It might take a while to provide some output ...")
        if len(agent_uid or '') > 0:
            request_uri = api+"/siaas-server/agents/history/"+agent_uid
        else:
            request_uri = api+"/siaas-server/agents/history"
        if hide:
            request_uri += "?hide=1"
        else:
            request_uri += "?hide=0"
        if older:
            request_uri += "&older=1"
        else:
            request_uri += "&older=0"
        request_uri += "&sort="+str(sort)
        request_uri += "&days="+str(days)
        request_uri += "&limit="+str(limit)
        if len(module or '') > 0:
            request_uri += "&module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)


@add_options(_cmd_options)
@click.option('-a', '--agent', help="Only shows results scanned by these agents (comma-separated).")
@click.option('-h', '--target-host', help="Only shows results targeting these hosts (comma-separated).")
@click.option('-t', '--report-type', help="Type of report to generate ('all', 'vuln_only', 'exploit_vuln_only'). (Default: 'vuln_only')", default="vuln_only")
@siaas.command("vuln-report")
def vuln_report(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, agent: str, target_host: str, report_type: str):
    """
    Reports scanned vulnerabilities.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    try:
        if len(agent or '') > 0:
            request_uri = api+"/siaas-server/agents/data/"+agent+"?module=portscanner"
        else:
            request_uri = api+"/siaas-server/agents/data?module=portscanner"
        r = requests.get(request_uri, timeout=timeout, verify=verify,
                         allow_redirects=True, auth=(user, password))
    except Exception as e:
        logger.error(
            "Error while performing a GET request to the server API: "+str(e))
        exit(1)
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the server API: " +
                     str(r.status_code))
        exit(1)
    if len(target_host or '') == 0:
        target_host = None
    vuln_dict = grab_vulns_from_agent_data_dict(
        r.json()["output"], target_host=target_host, report_type=report_type)
    if vuln_dict == False:
        logger.error("There was an error getting vulnerability dict.")
        exit(1)
    print_pretty_output(vuln_dict, indent_spaces, colors)
    exit(0)

@siaas.command("zap-config-show")
@add_options(_cmd_options)
@click.argument('section', required=False)
def zap_config_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, section: str):
    """
    Shows the ZAP or automation plan configurations. Optionally specify a section.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    
    try:
        if section:
            request_uri = f"{api}/siaas-server/siaas-zap/config/{section}"
        else:
            request_uri = f"{api}/siaas-server/siaas-zap/config"
        
        r = requests.get(request_uri, timeout=timeout, verify=verify, auth=(user, password))
    except Exception as e:
        logger.error("Error while performing a GET request to the server API: " + str(e))
        exit(1)
        
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting configuration data from the server API: " + str(r.status_code))
        exit(1)
        
@siaas.command("zap-config-update")
@add_options(_cmd_options)
@click.argument('section', required=True)
@click.option('--value', required=True, help="New value for the configuration key (in JSON format).")
def zap_config_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, section: str, value: str):
    """
    Updates the value for existing keys in a specific section.
    The key must already exist in the configuration.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    
    try:
        # Convert value from JSON string to Python dictionary
        data = json.loads(value)
        
        request_uri = f"{api}/siaas-server/siaas-zap/config/{section}"
        
        # Fetch current configuration to ensure keys exist
        r_get = requests.get(request_uri, timeout=timeout, verify=verify, auth=(user, password))
        if r_get.status_code != 200:
            logger.error("Error fetching current configuration from the server API: " + str(r_get.status_code))
            exit(1)
        
        current_config = r_get.json().get(section, {})
        
        # Ensure all keys in the update exist in the current config
        for key in data:
            if key not in current_config:
                logger.error(f"Key '{key}' does not exist in section '{section}'. Cannot update non-existing keys.")
                exit(1)
        
        # Send the updated values
        r_post = requests.post(request_uri, json=data, timeout=timeout, verify=verify, auth=(user, password))
    except json.JSONDecodeError:
        logger.error("Invalid JSON format for value.")
        exit(1)
    except Exception as e:
        logger.error("Error while performing a POST request to the server API: " + str(e))
        exit(1)
        
    if r_post.status_code == 200:
        print("Configuration updated successfully.")
        exit(0)
    else:
        logger.error("Error updating configuration on the server API: " + str(r_post.status_code))
        exit(1)

@siaas.command("zap-targets-list")
@add_options(_cmd_options)
def zap_targets_list(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool):
    """
    Lists all targets that have been analyzed (only target names).
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    
    try:
        request_uri = api + "/siaas-server/siaas-zap/results"
        r = requests.get(request_uri, timeout=timeout, verify=verify, auth=(user, password))
    except Exception as e:
        logger.error("Error while performing a GET request to the server API: " + str(e))
        exit(1)
        
    if r.status_code == 200:
        results = r.json().get('output', [])
        targets = [result.get('target') for result in results if 'target' in result]
        for target in targets:
            print(target)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " + str(r.status_code))
        exit(1)

@siaas.command("zap-results-show")
@add_options(_cmd_options)
@click.argument('target', required=True)
@click.option('--risk', default=None, help="Comma-separated risk levels to filter alerts (e.g., High,Medium).")
def zap_results_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, target: str, risk: str):
    """
    Shows results for a specific target, with optional risk filtering.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    
    try:
        request_uri = f"{api}/siaas-server/siaas-zap/results/{target}"
        params = {'risk': risk} if risk else {}
        r = requests.get(request_uri, params=params, timeout=timeout, verify=verify, auth=(user, password))
    except Exception as e:
        logger.error("Error while performing a GET request to the server API: " + str(e))
        exit(1)
        
    if r.status_code == 200:
        print_pretty_output(r.json(), indent_spaces, colors)
        exit(0)
    else:
        logger.error("Error getting data from the server API: " + str(r.status_code))
        exit(1)

@siaas.command("zap-results-delete")
@add_options(_cmd_options)
@click.argument('target', required=True)
def zap_results_delete(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, indent_spaces: int, colors: bool, target: str):
    """
    Deletes results for a specific target.
    """
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure == True:
        logger.warning(
            "SSL verification is off! The validity of the CA is not being verified.")
        verify = False
    else:
        if len(ca_bundle or '') > 0:
            verify = ca_bundle
        else:
            verify = True
    
    try:
        request_uri = f"{api}/siaas-server/siaas-zap/results/{target}"
        r = requests.delete(request_uri, timeout=timeout, verify=verify, auth=(user, password))
    except Exception as e:
        logger.error("Error while performing a DELETE request to the server API: " + str(e))
        exit(1)
        
    if r.status_code == 200:
        print("Target deleted successfully.")
        exit(0)
    else:
        logger.error("Error deleting data from the server API: " + str(r.status_code))
        exit(1)


if __name__ == '__main__':
    siaas(prog_name='siaas-cli')
