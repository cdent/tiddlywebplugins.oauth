"""
Data handling code used by an oauth2 provider.
"""

import json
from base64 import b64decode
from uuid import uuid4
from datetime import datetime, timedelta
from httpexceptor import HTTP302

from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.store import StoreError
from tiddlyweb.web.util import (http_date_from_timestamp,
        datetime_from_http_date, encode_name)

from tiddlywebplugins.utils import require_any_user
from tiddlywebplugins.templates import get_template

from .client import get_app, client_valid


@require_any_user()
def provider_auth(environ, start_response):
    """
    Authorize endpoint on the provider.

    If the right information is provided and validates against
    stored info, and the user says it is okay, return a
    code back to the redirect_uri, which must begin with
    the stored callback_url.

    That code is stored to be compared later, when the
    consumer sends it requesting as access_token.

    XXX: Missing scope handling.
    """
    query = environ['tiddlyweb.query']
    data = {}
    input_errors = False
    for key in ['redirect_uri', 'scope', 'response_type', 'client_id',
            'access_type', 'state']:
        if key in query:
            data[key] = query[key][0]
        elif key in ['client_id', 'response_type', 'scope']:
            input_errors = True

    try:
        app = get_app(environ, data['client_id'])
    except (StoreError, KeyError):
        return provider_auth_error(data, error='unauthorized_client')

    if 'redirect_uri' not in data:
        data['redirect_uri'] = app.fields['callback_url']

    # This comes after loading the app, as we might not have a
    # redirect uri
    if input_errors:
        provider_auth_error(data, error='invalid_request')

    if not data['redirect_uri'].startswith(app.fields['callback_url']):
        return provider_auth_error(data, error='invalid_request')

    # XXX check scope

    data['name'] = app.fields['name']

    if already_authorized(environ, app):
        return provider_auth_success(environ, data)

    if environ['REQUEST_METHOD'] == 'GET':
        template = get_template(environ, 'provider_auth.html')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=UTF-8')])
        return template.generate(data=data)
    else:
        if 'accept' in query:
            save_provider_auth(environ, data)
            return provider_auth_success(environ, data)
        else:
            return provider_auth_error(data, error='access_denied')


def provider_auth_success(environ, data):
    """
    Provider responds to authorize requests with redirect
    including code.
    """
    user = environ['tiddlyweb.usersign']['name']
    redirect_uri = data['redirect_uri']
    try:
        auth_code = register_code(environ, user=user, client=data['client_id'],
                redirect=redirect_uri, scope=data['scope'])
    except StoreError:
        return provider_auth_error(data, error='server_error')

    redirect_data = 'code=%s' % auth_code
    if 'state' in data:
        redirect_data += '&state=%s' % encode_name(data['state'])
    if '?' in redirect_uri:
        redirect_uri += '&%s' % redirect_data
    else:
        redirect_uri += '?%s' % redirect_data

    raise HTTP302(redirect_uri)


def provider_auth_error(data, error='invalid_request'):
    """
    Provider responds to the redirect_url with error.
    """
    redirect_uri = data['redirect_uri']
    if '?' in redirect_uri:
        redirect_uri += '&error=%s' % error
    else:
        redirect_uri += '?error=%s' % error

    raise HTTP302(redirect_uri)


def access_token(environ, start_response):
    """
    On the auth server, respond to a POST requesting an access
    token. This request comes from the client (aka the consumer),
    following the resource owner (aka the user-agent) authorizing
    the client to the auth server.

    There are several required form items. Once these are had,
    the client_secret and id must be validated against stored info.

    Then the code must be checked against storage. If it is too
    old (over 1 minute) we will not use it.

    If everything is okay we create an access token that is limited
    to a particular user, client and scope and send that in the
    response.
    """
    query = environ['tiddlyweb.query']
    input_data = {}
    for key in ['grant_type', 'code', 'scope', 'client_id', 'client_secret',
            'redirect_uri']:
        try:
            input_data[key] = query[key][0]
        except KeyError:
            return token_error(start_response,
                    error='invalid_request',
                    message='missing required input')

    # Extract client auth info, either from POST or HTTP Basic auth
    try:
        input_data['client_id'] = query['client_id'][0]
        input_data['client_secret'] = query['client_secret'][0]
    except KeyError:
        client_info = environ.get('HTTP_AUTHORIZATION', 'Basic ').split(' ')[1]
        client_info = b64decode(client_info).split(':')
        input_data['client_id'] = client_info[0]
        input_data['client_secret'] = client_info[1]

    if not client_valid(environ, input_data['client_id'],
            input_data['client_secret']):
        return token_error(start_response, error='invalid_client')

    if input_data['grant_type'] != 'authorization_code':
        return token_error(start_response,
                error='invalid_grant',
                message='authorization_code only')

    try:
        registration = get_code(environ, input_data['code'])
    except StoreError:
        return token_error(start_response,
                error='invalid_client', message='bad code')

    if code_expired(registration):
        delete_code(environ, registration)
        return token_error(start_response,
                error='invalid_client', message='code expired')

    # XXX scope handling more full
    if not input_data['scope']:
        try:
            scope = registration.fields['scope']
        except KeyError:
            scope = ''
    else:
        scope = input_data['scope']

    if registration.fields['redirect_uri'] != input_data['redirect_uri']:
        return token_error(start_response,
                error='invalid_client', message='redirect_uri does not match')

    code_user = registration.modifier
    delete_code(environ, registration)

    try:
        token = make_access_token(environ, user=code_user,
                client=input_data['client_id'], scope=scope)
    except StoreError:
        return token_error(start_response,
                error='server_error',
                message='unable to save access token')

    return token_success(start_response, token)


def token_success(start_response, token):
    """
    Provider responds with an access token.
    """
    data = {'access_token': token.title,
            'token_type': token.fields['token_type'],
            'scope': token.fields['scope']}
    if 'expires_in' in token.fields:
        data['expires_in'] = token.fields['expires_in']

    json_data = json.dumps(data)
    start_response('200 OK', [
        ('Content-Type', 'application/json'),
        ('Cache-control', 'no-store'),
        ('Pragma', 'no-cache')])
    return [json_data]


def token_error(start_response, error='error', message=''):
    """
    Provider responds to token request with an error.
    """
    data = {'error': error}
    if message:
        data['error_description'] = message
    json_data = json.dumps(data)
    start_response('400 Bad Request', [
        ('Content-type', 'application/json'),
        ('Cache-control', 'no-store'),
        ('Pragma', 'no-cache')])
    return [json_data]


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
            'client': client,
            'scope': scope}
    if expires_in:
        token.fields['expires_in'] = expires_in

    store.put(token)

    return token
