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
@siaas.command()
def api(api: str, user: str, password: str, ca_bundle: str, insecure: bool):
    """
    Shows SIAAS API information.
    """
    urllib3.disable_warnings()
    if insecure==True:
       logger.warning("SSL verification is off! This might have security implications while connecting to the server API.")
       verify=False
    else:
       if len(ca_bundle or '')>0:
         verify=ca_bundle
       else:
         verify=True
    try:
        r = requests.get(api+"/", timeout=60, verify=verify, allow_redirects=True, auth=(user,password))
    except Exception as e:
        logger.error("Error while performing a GET request to the server API: "+str(e))
        return False
    if r.status_code == 200:
        logger.debug("All data that was read from the server API:\n" +
                     pprint.pformat(r.json()))
        print(pprint.pformat(r.json()))
    else:
        logger.error("Error getting data from the server API: "+str(r.status_code))


if __name__ == '__main__':
    siaas(prog_name='siaas-cli')
