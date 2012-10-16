
from tiddlywebplugins.utils import require_any_user

from tiddlyweb.store import StoreError
from tiddlyweb.web.http import HTTP302, HTTP303, HTTP400, HTTP404
from tiddlyweb.web.util import server_base_url

from .auth import get_flow_client, get_auth_uri, get_credentials
from .app import create_app, store_app, get_app

def do_user_auth(environ, start_response):
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


@require_any_user()
def createclient(environ, start_response):
    query = environ['tiddlyweb.query']
    current_user = environ['tiddlyweb.usersign']['name']
    data = {}
    for key in ['name', 'app_url', 'callback_url', 'logo']:
        if key in query:
            data[key] = query[key][0]
    data['owner'] = current_user

    try:
        app_tiddler = create_app(**data)
    except TypeError as exc:
        raise HTTP400('Invalid form submission: %s' % exc)

    # let a store error raise to a 500 (for now)
    app_tiddler = store_app(environ, app_tiddler)

    raise HTTP303(server_base_url(environ)
            + '/_oauth/clientinfo?app=%s' % app_tiddler.title)


def clientinfo(environ, start_response):
    query = environ['tiddlyweb.query']
    current_user = environ['tiddlyweb.usersign']['name']
    app_id = query.get('app', [None])[0]

    if not app_id:
        raise HTTP400('app parameter required')

    try:
        app = get_app(environ, app_id)
    except StoreError:
        raise HTTP404('no matching app found')

    start_response('200 OK', [(
        'Content-Type', 'text/plain; charset=UTF-8')])

    output = ['client id: %s' % app.title]
    if current_user == app.modifier:
        output.append('client secret: %s' % app.fields['client_secret'])
    return output


def init(config):
    if 'selector' in config:
        config['selector'].add('/oauth2callback', GET=do_user_auth)
        config['selector'].add('/_oauth/createclient', POST=createclient)
        config['selector'].add('/_oauth/clientinfo', GET=clientinfo)
