import click
import requests
import urllib3
import pprint
import logging
import os

logger = logging.getLogger(__name__)
try:
   log_level=eval("logging."+os.getenv('SIAAS_LOG_LEVEL').upper())
except:
   log_level=logging.WARN
logging.basicConfig(level=log_level)

@click.group()
@click.version_option(version="1.0.0")
def siaas():
    """A CLI wrapper for the SIAAS API."""

@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@siaas.command("api-show")
def api_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool):
    """
    Shows API information.
    """
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
        r = requests.get(api, timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@siaas.command("server-show")
def server_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool):
    """
    Shows server information.
    """
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
        r = requests.get(api+"/siaas-server", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@siaas.command("server-configs-show")
def server_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool):
    """
    Shows configs for the server.
    """
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
        r = requests.get(api+"/siaas-server/configs", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@siaas.command("agents-show")
def agents_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool):
    """
    Shows agents information.
    """
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
        r = requests.get(api+"/siaas-server/agents", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-data-show")
def agents_data_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, agent_uid: str):
    """
    Shows most recent data/metrics from agents.
    """
    urllib3.disable_warnings()
    print(str(agent_uid))
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
           r = requests.get(api+"/siaas-server/agents/data/"+agent_uid, timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
        else:
           r = requests.get(api+"/siaas-server/agents/data", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-configs-show")
def agents_configs_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, agent_uid: str):
    """
    Shows configs for the agents.
    """
    urllib3.disable_warnings()
    print(str(agent_uid))
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
           r = requests.get(api+"/siaas-server/agents/configs/"+agent_uid, timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
        else:
           r = requests.get(api+"/siaas-server/agents/configs", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


@click.option('-a', '--api', help="SIAAS API URI.", envvar='SIAAS_API_URI')
@click.option('-u', '--user', help="SIAAS API user.", envvar='SIAAS_API_USER')
@click.option('-p', '--password', help="SIAAS API password.", envvar='SIAAS_API_PWD')
@click.option('-c', '--ca_bundle', help="SIAAS SSL CA bundle path.", envvar='SIAAS_API_SSL_CA_BUNDLE')
@click.option('-i', '--insecure', is_flag=True, help="Don't verify SSL endpoint.", envvar='SIAAS_API_SSL_IGNORE_VERIFY')
@click.argument('agent_uid', nargs=1, required=0)
@siaas.command("agents-history-show")
def agents_history_show(api: str, user: str, password: str, ca_bundle: str, insecure: bool, agent_uid: str):
    """
    Shows historical data from agents.
    """
    urllib3.disable_warnings()
    print(str(agent_uid))
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
           r = requests.get(api+"/siaas-server/agents/history/"+agent_uid, timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
        else:
           r = requests.get(api+"/siaas-server/agents/history", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the API: "+str(r.status_code))


if __name__ == '__main__':
    siaas(prog_name='siaas-cli')
