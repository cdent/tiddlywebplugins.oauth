

from uuid import uuid4
from tiddlyweb.model.tiddler import Tiddler


def register_code(environ, user, client, redirect, scope=None):
    """
    Create and save a unique code for this authorization.
    """
    config = environ['tiddlyweb.config']
    store = environ['tiddlyweb.store']
    if scope is None:
        scope = []
    code = str(uuid4())
    registration = Tiddler(code)
    registration.fields = dict(
            user=user,
            client=client,
            redirect_uri=redirect,
            scope=','.join(scope))

    bag_name = config.get('oauth.registrations_bag', 'oauth_registrations')
    registration.bag = bag_name

    store.put(registration)

    return code
    

def save_provider_auth(environ, data):
    """
    Record that this user has accept auth for this app.
    To be used by already_authorized()
    """
    pass

def already_authorized(environ, data):
    """
    Return true or false if this current user has an existing
    validation of this app.
    """
    return False

