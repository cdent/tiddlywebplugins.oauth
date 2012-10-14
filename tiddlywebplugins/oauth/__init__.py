
from oauth2client.client import OAuth2WebServerFlow

from copy import deepcopy
from httplib2 import Http

from tiddlyweb.web.http import HTTP302


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


def doAuth(environ, start_response):
    query = environ['tiddlyweb.query']

    config = environ['tiddlyweb.config']

    code = query.get('code', [None])[0]
    error = query.get('error', [None])[0]
    server_name = query.get('server_name', [None])[0]

    # initial redirect
    if not code and not error: 
        raise HTTP302(get_auth_uri(config, server_name))

    output = []
    if code:
        output.append('code: %s\n' % code)
        credentials, http = get_credentials(config, server_name, code)
        output.append('credentials: %s\n' % credentials)
        credentials.authorize(http)
        response, content = http.request(
                config['oauth.servers'][server_name]['info_uri'])
        output.append(content)

    start_response('200 OK', [('Content-Type', 'text-plain')])
    return output


def init(config):
    if 'selector' in config:
        config['selector'].add('/oauth2callback', GET=doAuth)
