

from uuid import uuid4
from datetime import datetime, timedelta

from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.web.util import (http_date_from_timestamp,
        datetime_from_http_date)


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
    registration.modifier = user
    registration.fields = dict(
            client=client,
            redirect_uri=redirect,
            scope=','.join(scope))

    bag_name = config.get('oauth.registrations_bag', 'oauth_registrations')
    registration.bag = bag_name

    store.put(registration)

    return code


def get_code(environ, code):
    """
    Load code data from the store
    """
    config = environ['tiddlyweb.config']
    store = environ['tiddlyweb.store']
    bag_name = config.get('oauth.registrations_bag', 'oauth_registrations')
    registration = Tiddler(code, bag_name)
    return store.get(registration)


def code_expired(registration):
    """
    Return true if this registration is out of date.
    """
    timestamp = registration.created
    created_time = datetime_from_http_date(http_date_from_timestamp(timestamp))
    return created_time < (datetime.utcnow() - timedelta(minutes=1))


def delete_code(environ, registration):
    """
    Delete this registration. It's either been used or is out of date.
    """
    store = environ['tiddlyweb.store']
    store.delete(registration)


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

