"""
Creation and updating of client apps.
"""

from uuid import uuid4

from tiddlyweb.model.tiddler import Tiddler


def create_app(name=None, owner=None, app_url=None,
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


def get_app(environ, app_id):
    """
    Get the app out of the store.
    """
    store = environ['tiddlyweb.store']
    config = environ['tiddlyweb.config']
    bag = config.get('oauth.app_bag', 'oauth_apps')
    app = Tiddler(app_id)
    app.bag = bag
    return store.get(app)


def client_valid(environ, client_id, client_secret):
    """
    Return true if the provided secret for client_id is the same as the
    one in storage.
    """
    app = get_app(environ, client_id)
    return app.fields['client_secret'] == client_secret
