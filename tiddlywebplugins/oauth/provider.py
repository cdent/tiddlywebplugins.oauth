

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


def make_access_token(environ, user, client, scope='', token_type='bearer',
        expires_in=None):
    """
    Create an access token for a user from a particular client and scope.
    """
    config = environ['tiddlyweb.config']
    store = environ['tiddlyweb.store']
    bag_name = config.get('oauth.tokens_bag', 'oauth_tokens')

    code = str(uuid4())
    token = Tiddler(code, bag_name)
    token.modifier = user
    token.fields = {
            'token_type': token_type,
            'scope': scope}
    if expires_in:
        token.fields['expires_in'] = expires_in

    store.put(token)

    return token


def check_access_token(environ, token):
    """
    Extract a user from token information, if the token is valid.
    """
    config = environ['tiddlyweb.config']
    store = environ['tiddlyweb.store']
    bag_name = config.get('oauth.tokens_bag', 'oauth_tokens')

    token_info = Tiddler(token, bag_name)
    token_info = store.get(token_info)
    token_type = token_info.fields['token_type']
    expires_in = token_info.fields.get('expires_in', None)
    if token_type != 'bearer':
        return None
    user = token_info.modifier
    if 'scope' in token_info.fields:
        scope = token_info.fields['scope'].split(' ')
    else:
        scope = ''

    if expires_in:
        # XXX check against token creation time delete if expired
        pass

    return user, scope

