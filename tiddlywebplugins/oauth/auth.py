

from oauth2client.client import OAuth2WebServerFlow
from copy import deepcopy
from httplib2 import Http

def get_flow_client(config, server_name):
    """
    Return a flow and an http object for running these requests.
    for this server_name. Return KeyError if the server is not
    configured.
    """
    config_data = deepcopy(config['oauth.servers'][server_name])
    if 'no_trust' in config_data:
        http = Http(disable_ssl_certificate_validation=True)
        del config_data['no_trust']
    else:
        http = Http()

    del config_data['info_uri']
    config_data['redirect_uri'] ='%s?server_name=%s' % (
            config_data['redirect_uri'], server_name)
    flow = OAuth2WebServerFlow(**config_data)

    return flow, http


def get_auth_uri(config, server_name):
    flow = get_flow_client(config, server_name)[0]
    auth_uri = flow.step1_get_authorize_url()
    return auth_uri


def get_credentials(config, server_name, code):
    flow, http = get_flow_client(config, server_name)
    credentials = flow.step2_exchange(code, http=http)
    return credentials, http


