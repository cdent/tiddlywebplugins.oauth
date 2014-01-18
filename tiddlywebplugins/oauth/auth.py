"""
Utility routines used by a consumer (server that wants
to access restriced resources on a provider) to follow
a web server flow for authorizing and getting an access
token.
"""

from oauth2client.client import OAuth2WebServerFlow
from copy import deepcopy
from httplib2 import Http


def get_flow_client(config, server_name, redirect_extra=None):
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
    redirect_uri =  '%s?server_name=%s' % (
            config_data['redirect_uri'], server_name)
    if redirect_extra:
        redirect_uri = redirect_uri + ';tiddlyweb_redirect=%s' % redirect_extra
    config_data['redirect_uri'] = redirect_uri
    flow = OAuth2WebServerFlow(**config_data)

    return flow, http


def get_auth_uri(config, server_name, redirect_extra=None):
    """
    Get the auth uri for a provider named by server_name.
    """
    flow = get_flow_client(config, server_name, redirect_extra)[0]
    auth_uri = flow.step1_get_authorize_url()
    return auth_uri


def get_credentials(config, server_name, code):
    """
    Do the HTTP to get an access token from server_name, using
    the provided code.
    """
    flow, http = get_flow_client(config, server_name)
    credentials = flow.step2_exchange(code, http=http)
    return credentials, http
