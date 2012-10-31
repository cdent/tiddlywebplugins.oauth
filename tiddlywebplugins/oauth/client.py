"""
Creation and updating of client apps.
"""

from uuid import uuid4

from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.store import StoreError
from tiddlyweb.web.http import HTTP303, HTTP400, HTTP404
from tiddlyweb.web.util import server_base_url

from tiddlywebplugins.utils import require_any_user

@require_any_user()
def create_app(environ, start_response):
    """
    At the provider, register a client and provide them with
    an id, secret, etc.

    This is not part of the oAuth spec, but is fairly standard
    form for what is usually called "creating an app".

    On success redirects to the info page for the app.
    """
    query = environ['tiddlyweb.query']
    current_user = environ['tiddlyweb.usersign']['name']
    data = {}
    for key in ['name', 'app_url', 'callback_url', 'logo']:
        if key in query:
            data[key] = query[key][0]
    data['owner'] = current_user

    try:
        app_tiddler = _create_app(**data)
    except TypeError as exc:
        raise HTTP400('Invalid form submission: %s' % exc)

    # let a store error raise to a 500 (for now)
    app_tiddler = store_app(environ, app_tiddler)

    raise HTTP303(server_base_url(environ)
            + '/_oauth/appinfo?app=%s' % app_tiddler.title)


def app_info(environ, start_response):
    """
    At the provider display the stored information
    about a app, given its id in the query parameter `app`.

    Only the client/app owner can see the secret.
    """
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


def _create_app(name=None, owner=None, app_url=None,
        callback_url=None, logo=None):
    """
    Create a tiddler representing a client app.
    """
    if not name or not owner or not app_url or not callback_url:
        raise TypeError('name, owner, app_url and callback_url required')

    client_id = str(uuid4())
    client_secret = str(uuid4())
    client = Tiddler(client_id)
    client.modifier = owner
    client.fields = {
            'client_secret': client_secret,
            'name': name,
            'app_url': app_url,
            'callback_url': callback_url}
    if logo:
        client.fields['logo'] = logo

    return client


def store_app(environ, app):
    """
    Write the tiddler that represents the app to the store.
    """
    store = environ['tiddlyweb.store']
    config = environ['tiddlyweb.config']
    bag = config.get('oauth.app_bag', 'oauth_apps')

    app.bag = bag
    store.put(app)
    return app


def get_app(environ, client_id):
    """
    Get the app out of the store.
    """
    store = environ['tiddlyweb.store']
    config = environ['tiddlyweb.config']
    bag = config.get('oauth.app_bag', 'oauth_apps')
    app = Tiddler(client_id)
    app.bag = bag
    return store.get(app)


def client_valid(environ, client_id, client_secret):
    """
    Return true if the provided secret for client_id is the same as the
    one in storage.
    """
    app = get_app(environ, client_id)
    return app.fields['client_secret'] == client_secret
