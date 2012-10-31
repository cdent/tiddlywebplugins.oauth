"""
Plugin initialization and web handlers for doing oauth.
These need to be split out into differnt files.
"""

import json


from tiddlyweb.store import StoreError
from tiddlyweb.web.http import HTTP302

from tiddlywebplugins.utils import require_any_user
from tiddlywebplugins.templates import get_template

from .client import create_app, app_info, get_app, client_valid
from .provider import (register_code, save_provider_auth, already_authorized,
        get_code, code_expired, delete_code, make_access_token)
from .consumer import do_user_auth


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
    for key in ['scope', 'redirect_uri', 'response_type', 'client_id',
            'access_type', 'state']:
        if key in query:
            data[key] = query[key][0]
        elif key in ['client_id', 'response_type', 'scope']:
            provider_auth_error(data, error='invalid_request')

    try:
        app = get_app(environ, data['client_id'])
    except StoreError:
        return provider_auth_error(data, error='unauthorized_client')

    if 'redirect_uri' not in data:
        data['redirect_uri'] = app.fields['callback_url']

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


def access_token(environ, start_response):
    """
    On the provider, respond to a POST requesting an access
    token.

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
        ('Cache-control', 'no-store')])
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
        ('Content-type', 'application/json')])
    return [json_data]


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
        redirect_data += '&state%s' % data['state']
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


@require_any_user()
def user_info(environ, start_response):
    """
    Simple handler which displays the current user's
    username and roles.
    """
    current_user = environ['tiddlyweb.usersign']
    json_data = json.dumps(current_user)
    start_response('200 OK', [
        ('Content-Type', 'application/json; charset=UTF-8')])
    return [json_data]


def init(config):
    """
    Initialize the plugin by setting handlers and adding
    extractor.
    """
    if 'selector' in config:
        config['extractors'].append('tiddlywebplugins.oauth.extractor')
        config['selector'].add('/_oauth/callback', GET=do_user_auth)
        config['selector'].add('/_oauth/createapp', POST=create_app)
        config['selector'].add('/_oauth/appinfo', GET=app_info)
        config['selector'].add('/_oauth/authorize', GET=provider_auth,
                POST=provider_auth)
        config['selector'].add('/_oauth/access_token', POST=access_token)
        config['selector'].add('/_oauth/user_info', GET=user_info)
