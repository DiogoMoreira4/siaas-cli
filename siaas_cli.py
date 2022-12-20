import click
import requests
import urllib3
import pprint
import logging
import os

logger = logging.getLogger(__name__)

SIAAS_VERSION = "1.0.0"

_cmd_options = [
    click.option('-A', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI'),
    click.option('-U', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER'),
    click.option('-P', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD'),
    click.option('-C', '--ca-bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE'),
    click.option('-I', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY'),
    click.option('-T', '--timeout', help="SIAAS SSL API timeout. (Default: 60)", envvar='SIAAS_API_TIMEOUT', default=60),
    click.option('-D', '--debug', is_flag=True, help="SIAAS debug logs. (Default: False)", envvar='SIAAS_DEBUG_LOGS')
]


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func
    return _add_options


def grab_vulns_from_agent_data_dict(agent_data_dict, target_host=None, report_type="exploit_only"):

    if len(report_type or '') == 0:
        report_type="exploit_only"

    new_dict={}

    if report_type.lower() == "all":
        try:
            for a in agent_data_dict.keys():
                for b in agent_data_dict[a].keys():
                    if b == "portscanner":
                        for c in agent_data_dict[a][b].keys():
                            if len(target_host or '') > 0 and c not in target_host.split(','):
                                 continue
                            if a not in new_dict.keys():
                                 new_dict[a]={}
                            if b not in new_dict[a].keys():
                                 new_dict[a][b]={}
                            new_dict[a][b][c]=agent_data_dict[a][b][c]
        except Exception as e:
           logger.error("Error generating new dict: "+str(e))
           return False
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
                                        new_dict[a]={}
                                    if b not in new_dict[a].keys():
                                        new_dict[a][b]={}
                                    if c not in new_dict[a][b].keys():
                                        new_dict[a][b][c]={}
                                    new_dict[a][b][c]["last_check"] = agent_data_dict[a][b][c]["last_check"]
                                if d == "scanned_ports":
                                    for e in agent_data_dict[a][b][c][d].keys():
                                        for f in agent_data_dict[a][b][c][d][e].keys():
                                            if f == "scan_results":
                                                for g in agent_data_dict[a][b][c][d][e][f].keys():
                                                    for h in agent_data_dict[a][b][c][d][e][f][g].keys():
                                                        if "vulners" in h or "vulscan" in h:
                                                            if report_type.lower() == "vuln_only":
                                                                if a not in new_dict.keys():
                                                                     new_dict[a]={}
                                                                if b not in new_dict[a].keys():
                                                                     new_dict[a][b]={}
                                                                if c not in new_dict[a][b].keys():
                                                                     new_dict[a][b][c]={}
                                                                if d not in new_dict[a][b][c].keys():
                                                                     new_dict[a][b][c][d]={}
                                                                if e not in new_dict[a][b][c][d].keys():
                                                                     new_dict[a][b][c][d][e]={}
                                                                if f not in new_dict[a][b][c][d][e].keys():
                                                                     new_dict[a][b][c][d][e][f]={}
                                                                if g not in new_dict[a][b][c][d][e][f].keys():
                                                                    new_dict[a][b][c][d][e][f][g]={}
                                                                new_dict[a][b][c][d][e][f][g][h]=agent_data_dict[a][b][c][d][e][f][g][h]
                                                            else: # exploit_only (default)
                                                                for i in agent_data_dict[a][b][c][d][e][f][g][h].keys():
                                                                    for j in agent_data_dict[a][b][c][d][e][f][g][h][i].keys():
                                                                        if "siaas_exploit_tag" in agent_data_dict[a][b][c][d][e][f][g][h][i][j]:
                                                                            if a not in new_dict.keys():
                                                                                new_dict[a]={}
                                                                            if b not in new_dict[a].keys():
                                                                                new_dict[a][b]={}
                                                                            if c not in new_dict[a][b].keys():
                                                                                new_dict[a][b][c]={}
                                                                            if d not in new_dict[a][b][c].keys():
                                                                                new_dict[a][b][c][d]={}
                                                                            if e not in new_dict[a][b][c][d].keys():
                                                                                new_dict[a][b][c][d][e]={}
                                                                            if f not in new_dict[a][b][c][d][e].keys():
                                                                                new_dict[a][b][c][d][e][f]={}
                                                                            if g not in new_dict[a][b][c][d][e][f].keys():
                                                                                new_dict[a][b][c][d][e][f][g]={}
                                                                            if h not in new_dict[a][b][c][d][e][f][g].keys():
                                                                                new_dict[a][b][c][d][e][f][g][h]={}
                                                                            if i not in new_dict[a][b][c][d][e][f][g][h].keys():
                                                                                new_dict[a][b][c][d][e][f][g][h][i]={}
                                                                            new_dict[a][b][c][d][e][f][g][h][i][j]=agent_data_dict[a][b][c][d][e][f][g][h][i][j]

        except Exception as e:
            logger.error("Error generating new dict: "+str(e))
            return False

    return new_dict


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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@siaas.command("server-configs-add-or-update")
def server_configs_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, key_value: str):
    """
    Adds or updates server configuration keys (accepts multiple configuration key=value pairs, comma-separated).
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
    pattern = "^[A-Za-z0-9_-]*$"
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    current_config_dict = {}
    delta_config_dict = {}
    current_config_dict = r.json()["output"]
    for kv in key_value.split(','):
        try:
           config_name = kv.split("=", 1)[0].rstrip().lstrip()
           config_value = kv.split("=", 1)[1].rstrip().lstrip()
        except Exception as e:
           logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
           continue
        delta_config_dict[config_name]=config_value
    try:
        new_config_dict = dict(list(current_config_dict.items()) + list(delta_config_dict.items()))
        request_uri = api+"/siaas-server/configs"
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was written to the API:\n" +
                      pprint.pformat(new_config_dict, sort_dicts=False))
        logger.debug("Posting output from the API:\n" +
                      pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error posting data to the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@siaas.command("server-configs-remove")
def server_configs_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, key: str):
    """
    Removes server configuration keys (accepts multiple configuration keys, comma-separated).
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
        request_uri = api+"/siaas-server/configs"
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    current_config_dict = {}
    current_config_dict = r.json()["output"]
    new_config_dict=dict(current_config_dict)
    for k in key.split(','):
        config_name = k.rstrip().lstrip()
        new_config_dict.pop(config_name, None)
    try:
        request_uri = api+"/siaas-server/configs"
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was written to the API:\n" +
                      pprint.pformat(new_config_dict, sort_dicts=False))
        logger.debug("Posting output from the API:\n" +
                      pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error posting data to the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@siaas.command("server-configs-clear")
def server_configs_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool):
    """
    Clears all server configuration keys.
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
        request_uri = api+"/siaas-server/configs"
        r = requests.delete(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("Deletion output from the API:\n" +
            pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error deleting data from the API: "+str(r.status_code))
        return False


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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these module(s) (comma-separated).")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-data-show")
def agents_data_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, module: str):
    """
    Shows most recent data/metrics from agents (accepts multiple agent UIDs, comma-separated).
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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.option('-d', '--days', help="Number of days to keep. (Default: 15)", default=15)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-data-delete")
def agents_data_delete(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, days: int):
    """
    Deletes agent data (accepts multiple agent UIDs, comma-separated).
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
        request_uri = api+"/siaas-server/agents/data/"+agent_uid
        request_uri += "?days="+str(days)
        r = requests.delete(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("Deletion output from the API:\n" +
            pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error deleting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.option('-b', '--broadcast', is_flag=True, help="Merge broadcast configurations.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-configs-show")
def agents_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, broadcast: bool):
    """
    Shows configs for the agents (accepts multiple agent UIDs, comma-separated).
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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-add-or-update")
def agents_configs_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, key_value: str):
    """
    Adds or updates agent configuration keys (accepts multiple agent UIDs and also multiple configuration key=value pairs, comma-separated).
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
    pattern = "^[A-Za-z0-9_-]*$"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    result=True
    for a in agent_uid.split(','):
        current_config_dict = {}
        delta_config_dict = {}
        if a in r.json()["output"].keys():
           current_config_dict = r.json()["output"][a]
        for kv in key_value.split(','):
           try:
              config_name = kv.split("=", 1)[0].rstrip().lstrip()
              config_value = kv.split("=", 1)[1].rstrip().lstrip()
           except Exception as e:
              logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
              continue
           delta_config_dict[config_name]=config_value
        try:
            new_config_dict = dict(list(current_config_dict.items()) + list(delta_config_dict.items()))
            request_uri = api+"/siaas-server/agents/configs/"+a
            r2 = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
        except Exception as e:
            logger.error(
                "Error while performing a POST request to the server API: "+str(e))
            result=False
        if r2.status_code == 200:
            logger.debug("All data that was written to the server API:\n" +
                          pprint.pformat(new_config_dict, sort_dicts=False))
            print(pprint.pformat(r2.json(), sort_dicts=False))
        else:
            logger.error("Error posting data to the server API: "+str(r2.status_code))
            result=False
    return result


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-remove")
def agents_configs_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, key: str):
    """
    Removes agent configuration keys (accepts multiple agent UIDs and also multiple configuration keys, comma-separated).
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
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    result=True
    for a in agent_uid.split(','):
        current_config_dict = {}
        if a in r.json()["output"].keys():
           current_config_dict = r.json()["output"][a]
        new_config_dict=dict(current_config_dict)
        for k in key.split(','):
           config_name = k.rstrip().lstrip()
           new_config_dict.pop(config_name, None)
        try:
           request_uri = api+"/siaas-server/agents/configs/"+a
           r2 = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
        except Exception as e:
            logger.error(
                "Error while performing a POST request to the server API: "+str(e))
            result=False
        if r2.status_code == 200:
            logger.debug("All data that was written to the server API:\n" +
                          pprint.pformat(new_config_dict, sort_dicts=False))
            print(pprint.pformat(r2.json(), sort_dicts=False))
        else:
            logger.error("Error posting data to the server API: "+str(r2.status_code))
            result=False
    return result

@add_options(_cmd_options)
@click.argument('agent_uid', nargs=1, required=1)
@siaas.command("agents-configs-clear")
def agents_configs_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str):
    """
    Clears all agent configuration keys (accepts multiple agent UIDs, comma-separated).
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
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.delete(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a request to the server API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("Output from the API:\n" +
            pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error interacting with the server API: "+str(r.status_code))
        return False

@add_options(_cmd_options)
@siaas.command("agents-configs-broadcast-show")
def agents_configs_broadcast_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool):
    """
    Shows broadcast configs for the agents.
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
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri=api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.argument('key_value', nargs=1, required=1)
@siaas.command("agents-configs-broadcast-add-or-update")
def agents_configs_broadcast_add_or_update(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, key_value: str):
    """
    Adds or updates agent broadcast configuration keys (accepts multiple configuration key=value pairs, comma-separated).
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
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    pattern = "^[A-Za-z0-9_-]*$"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    current_config_dict = {}
    delta_config_dict = {}
    if agent_uid in r.json()["output"].keys():
        current_config_dict = r.json()["output"][agent_uid]
    for kv in key_value.split(','):
        try:
           config_name = kv.split("=", 1)[0].rstrip().lstrip()
           config_value = kv.split("=", 1)[1].rstrip().lstrip()
        except Exception as e:
           logger.warning("Key-value '"+str(kv)+"' was ignored: "+str(e))
           continue
        delta_config_dict[config_name]=config_value
    try:
        new_config_dict = dict(list(current_config_dict.items()) + list(delta_config_dict.items()))
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was written to the API:\n" +
                      pprint.pformat(new_config_dict, sort_dicts=False))
        logger.debug("Posting output from the API:\n" +
                      pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error posting data to the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.argument('key', nargs=1, required=1)
@siaas.command("agents-configs-broadcast-remove")
def agents_configs_broadcast_remove(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, key: str):
    """
    Removes agent broadcast configuration keys (accepts multiple configuration keys, comma-separated).
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
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
               pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    current_config_dict = {}
    if agent_uid in r.json()["output"].keys():
        current_config_dict = r.json()["output"][agent_uid]
    new_config_dict=dict(current_config_dict)
    for k in key.split(','):
        config_name = k.rstrip().lstrip()
        new_config_dict.pop(config_name, None)
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.post(request_uri, json=new_config_dict, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a POST request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was written to the API:\n" +
                      pprint.pformat(new_config_dict, sort_dicts=False))
        logger.debug("Posting output from the API:\n" +
                      pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error posting data to the API: "+str(r.status_code))
        return False

@add_options(_cmd_options)
@siaas.command("agents-configs-broadcast-clear")
def agents_configs_broadcast_clear(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool):
    """
    Clears all agent broadcast configuration keys.
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
    agent_uid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    try:
        request_uri = api+"/siaas-server/agents/configs/"+agent_uid
        r = requests.delete(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error(
            "Error while performing a DELETE request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("Deletion output from the API:\n" +
            pprint.pformat(r.json(), sort_dicts=False))
        print(pprint.pformat(r.json(), sort_dicts=False))
        return True
    else:
        logger.error("Error deleting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.option('-m', '--module', help="Only show these module(s) (comma-separated).")
@click.option('-l', '--limit', help="Max number of records to show. (0 means no limit). (Default: 100)", default=100)
@click.option('-d', '--days', help="Max number of days to show. (Default: 2)", default=2)
@click.option('-s', '--sort', help="Use 'agent' or 'date' to sort. (Default: 'date')", default="date")
@click.option('-o', '--older', is_flag=True, help="Show older records first.")
@click.option('-h', '--hide', is_flag=True, help="Hide empty entries.")
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-history-show")
def agents_history_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent_uid: str, module: str, limit: int, days: int, sort: str, older: bool, hide: bool):
    """
    Shows historical data from agents (accepts multiple agent UIDs, comma-separated).
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
        return True
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False


@add_options(_cmd_options)
@click.option('-a', '--agent', help="Only shows results scanned by these agent(s) (comma-separated).")
@click.option('-t', '--target-host', help="Only shows results targeting these host(s) (comma-separated).")
@click.option('-r', '--report-type', help="Type of report to generate ('all', 'vuln_only', 'exploit_only'). (Default: 'exploit_only')", default="exploit_only")
@siaas.command("vuln-report")
def vuln_report(api: str, user: str, password: str, ca_bundle: str, insecure: bool, timeout: int, debug: bool, agent: str, target_host: str, report_type: str):
    """
    Reports scanned vulnerabilities.
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
        if len(agent or '') > 0:
           request_uri=api+"/siaas-server/agents/data/"+agent+"?module=portscanner"
        else:
           request_uri=api+"/siaas-server/agents/data?module=portscanner"
        r = requests.get(request_uri, timeout=timeout, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json(), sort_dicts=False))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))
        return False
    if len(target_host or '') == 0:
        target_host=None
    vuln_dict=grab_vulns_from_agent_data_dict(r.json()["output"], target_host=target_host, report_type=report_type)
    if vuln_dict == False:
        logger.error("There was an error getting vulnerability dict.")
        return False

    logger.debug("All data returned by the grabbing vuln function:\n" +
                     pprint.pformat(vuln_dict, sort_dicts=False))
    print(pprint.pformat(vuln_dict, width=500, sort_dicts=False))

if __name__ == '__main__':
    siaas(prog_name='siaas-cli')

