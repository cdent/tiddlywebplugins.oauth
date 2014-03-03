"""
Routines used by the oAuth2 client, aka the consumer.

For now this module hosts a client callback that was
created for the express purpose of allowing new user
registration in TiddlyWeb, using auth info from a
remote service such as Facebook, Github, Google.

As such, it extends the generic purpose of the
callback uri beyond what it would normally be.

A more generic tool would simply store the code
for future requests. So, for the future these
two purposes need to be separated.
"""

import simplejson

from oauth2client.client import Error as OAuthError
from httpexceptor import HTTP302, HTTP400

from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.model.user import User
from tiddlyweb.store import StoreError
from tiddlyweb.util import sha
from tiddlyweb.web.util import make_cookie, server_host_url

from tiddlywebplugins.templates import get_template

from .auth import get_auth_uri, get_credentials


def do_user_auth(environ, start_response):
    """
    Consumer authorization for the sake of a user.

    If no `code` is present then we send the user to the
    auth uri of the selected provider. If there is a code
    then we use that to get an access token, then use that
    access token to get some information about the user
    at the provider.

    XXX: Save the access token for later use.
    """

    query = environ['tiddlyweb.query']
    config = environ['tiddlyweb.config']

    code = query.get('code', [None])[0]
    error = query.get('error', [None])[0]
    server_name = query.get('server_name', [None])[0]
    redirect_uri = query.get('tiddlyweb_redirect', [None])[0]

    if not server_name:
        raise HTTP400('invalid request, server_name required')

    # initial redirect
    if not code and not error:
        raise HTTP302(get_auth_uri(config, server_name, redirect_uri))

    response_map = config['oauth.servers'][server_name].get('response_map')

    output = []
    if code:
        try:
            credentials, http = get_credentials(config, server_name, code)
        except OAuthError as exc:
            raise HTTP400('credentials failure: %s' % exc)

        credentials.authorize(http)
        response, content = http.request(
                config['oauth.servers'][server_name]['info_uri'])
        if response['status'] == '200':
            if response_map:
                return _do_login_or_register(environ, start_response,
                        server_name, response_map, content)
            else:
                output.append('code: %s\n' % code)
                output.append(content)
        else:
            output.append('Unable to reach info_uri')

    if error:
        output.append('error: %s\n' % error)

    start_response('200 OK', [('Content-Type', 'text-plain')])
    return output


def _do_login_or_register(environ, start_response, server_name, response_map,
        content):
    """
    We had a valid response from the oauth provider, let's see if that is
    a user or somebody we can register.
    """
    store = environ['tiddlyweb.store']
    config = environ['tiddlyweb.config']
    userinfo = simplejson.loads(content)
    userdata = {}
    for key, value in response_map.iteritems():
        userdata[key] = userinfo.get(value, '')

    server_login = None

    username = userdata['login']
    if not username:
        raise HTTP400('extractable username data required')

    userdata['server_name'] = server_name

    if config.get('oauth.use_mapuser', False):
        server_login = '%s-%s' % (server_name, username)
        map_bag_name = config.get('magicuser.map', 'MAPUSER')
        tiddler = Tiddler(server_login, map_bag_name)
        try:
            tiddler = store.get(tiddler)
            mapped_user = tiddler.fields.get('mapped_user')
            store.get(User(mapped_user))
            user = User(server_login)
            return _send_cookie(environ, start_response, user)
        except StoreError:
            try:
                local_user = store.get(User(username))
            except StoreError:
                local_user = None
            pass  # fall through to register
    else:
        try:
            user = store.get(User(username))
            return _send_cookie(environ, start_response, user)
        except StoreError:
            local_user = None
            pass  # fall through to register

    registration_template = get_template(environ, 'registration.html')

    start_response('200 OK', [('Content-Type', 'text/html; charset=UTF-8'),
        ('Cache-Control', 'no-store')])

    if local_user:
        userdata['local_user'] = local_user.usersign
    userdata['server_name_sig'] = _sign(config, server_name)
    if server_login:
        userdata['server_login'] = server_login
        userdata['server_login_sig'] = _sign(config, server_login)
    return registration_template.generate(userdata)


def _sign(config, item):
    """
    Make a hash of item.
    """
    secret = config['secret']
    return sha('%s%s' % (item, secret)).hexdigest()

def _send_cookie(environ, start_response, user):
    """
    We are authentic and a user exists, so install a cookie.
    """
    query = environ['tiddlyweb.query']
    tiddlyweb_redirect = query.get('tiddlyweb_redirect', [None])[0]
    config = environ['tiddlyweb.config']
    if not tiddlyweb_redirect:
        tiddlyweb_redirect = config.get('logged_in_redirect', '/')
    redirect_uri = '%s%s' % (server_host_url(environ), tiddlyweb_redirect)
    secret = config['secret']
    cookie_age = config.get('cookie_age', None)
    cookie_header_string = make_cookie('tiddlyweb_user', user.usersign,
            mac_key=secret, path='/', expires=cookie_age)
    start_response('303 See Other', 
            [('Set-Cookie', cookie_header_string),
                ('Content-Type', 'text/plain'),
                ('Location', str(redirect_uri))])
    return [redirect_uri]
