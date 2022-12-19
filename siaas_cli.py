import click
import requests
import urllib3
import pprint
import logging
import os

logger = logging.getLogger(__name__)

SIAAS_VERSION = "1.0.0"

_cmd_options = [
    click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI'),
    click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER'),
    click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD'),
    click.option('-c', '--ca-bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE'),
    click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY'),
    click.option('-t', '--timeout', help="SIAAS SSL API timeout. (Default: 60)", envvar='SIAAS_API_TIMEOUT', default=60),
    click.option('-d', '--debug', is_flag=True, help="SIAAS debug logs. (Default: False)", envvar='SIAAS_DEBUG_LOGS')
]

def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func
    return _add_options

@click.group()
@click.version_option(version=SIAAS_VERSION)
def siaas():
    """A CLI wrapper for the SIAAS API."""

@add_options(_cmd_options)
@siaas.command("api-show")
def api_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool):
    """
    Shows API information.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        r = requests.get(api, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these module(s) (comma-separated).")
@siaas.command("server-show")
def server_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, module: str):
    """
    Shows server information.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        request_uri=api+"/siaas-server"
        if len(module or '') > 0:
            request_uri+="?module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@siaas.command("server-configs-show")
def server_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool):
    """
    Shows configs for the server.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        r = requests.get(api+"/siaas-server/configs", timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@click.option('-s', '--sort', help="Use 'agent' or 'date' to sort. (Default: 'date')", default="date")
@siaas.command("agents-show")
def agents_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, sort: str):
    """
    Shows agents information.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        request_uri=api+"/siaas-server/agents"
        request_uri+="?sort="+sort
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))

    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these module(s) (comma-separated).")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-data-show")
def agents_data_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, module: str):
    """
    Shows most recent data/metrics from agents.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        if len(agent_uid or '') > 0:
           request_uri=api+"/siaas-server/agents/data/"+agent_uid
        else:
           request_uri=api+"/siaas-server/agents/data"
        if len(module or '') > 0:
            request_uri+="?module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@click.option('-b', '--broadcast', is_flag=True, help="Merge broadcast configurations.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-configs-show")
def agents_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, broadcast: bool):
    """
    Shows configs for the agents.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        if len(agent_uid or '') > 0:
           request_uri=api+"/siaas-server/agents/configs/"+agent_uid
        else:
           request_uri=api+"/siaas-server/agents/configs"
        if broadcast:
           request_uri+="?merge_broadcast=1"
        else:
           request_uri+="?merge_broadcast=0"
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these module(s) (comma-separated).")
@click.option('-l', '--limit', help="Max number of records to show. (0 means no limit). (Default: 100)", default=100)
@click.option('-j', '--days', help="Max number of days to show. (Default: 2)", default=2)
@click.option('-s', '--sort', help="Use 'agent' or 'date' to sort. (Default: 'date')", default="date")
@click.option('-o', '--older', is_flag=True, help="Show older records first.")
@click.option('-h', '--hide', is_flag=True, help="Hide empty entries.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-history-show")
def agents_history_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, module: str, limit: int, days: int, sort: str, older: bool, hide: bool):
    """
    Shows historical data from agents.
    """
    if debug:
       log_level=logging.DEBUG
    else:
       log_level=logging.WARN
    logging.basicConfig(level=log_level)
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        if len(agent_uid or '') > 0:
           request_uri=api+"/siaas-server/agents/history/"+agent_uid
        else:
           request_uri=api+"/siaas-server/agents/history"
        if hide:
           request_uri+="?hide=1"
        else:
           request_uri+="?hide=0"
        if older:
           request_uri+="&older=1"
        else:
           request_uri+="&older=0"
        request_uri+="&sort="+str(sort)
        request_uri+="&days="+str(days)
        request_uri+="&limit="+str(limit)
        if len(module or '') > 0:
           request_uri+="&module="+module
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        print(str(hide))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))

"""
TO DO:

server-configs-add-or-update
server-configs-remove
server-configs-clear
agents-data-delete <agent_uid>
agents-configs-add-or-update <agent_uid> <key:value>
agents-configs-remove <agent_uid> <key>
agents-configs-clear <agent_uid>
agents-configs-broadcast-add-or-update <key:value>
agents-configs-broadcast-remove <key>
agents-configs-broadcast-clear

"""

if __name__ == '__main__':
    siaas(prog_name='siaas-cli')

