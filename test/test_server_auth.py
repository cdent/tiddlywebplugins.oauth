from base64 import b64encode

from tiddlyweb.config import config
from tiddlyweb.model.user import User
from tiddlywebplugins.utils import get_store, ensure_bag

from tiddlywebplugins.oauth.app import create_app, store_app
from tiddlywebplugins.oauth.auth import get_auth_uri, get_credentials

from httplib2 import Http

from test.fixtures import initialize_app, clean_store

authorization = b64encode('cdent:cowpig')


def setup_module(module):
    """
    clean up the store, establish a registered client
    """
    clean_store()
    module.store = get_store(config)
    environ = {'tiddlyweb.config': config, 'tiddlyweb.store': module.store}

# set up required bags

# one for storing app info
    ensure_bag('oauth_apps', module.store, policy_dict=dict(
        read=['NONE'], write=['NONE'], create=['NONE'],
        delete=['NONE'], manage=['NONE']))

# one for storing user authorization codes

    ensure_bag('oauth_registrations', module.store, policy_dict=dict(
        read=['NONE'], write=['NONE'], create=['NONE'],
        delete=['NONE'], manage=['NONE']))

# one for storing user auth tokens
    ensure_bag('oauth_tokens', module.store, policy_dict=dict(
        read=['NONE'], write=['NONE'], create=['NONE'],
        delete=['NONE'], manage=['NONE']))

# make an application and store that info
    app = create_app(name='testapp', owner='cdent',
            app_url='http://our_test_domain:8001',
            callback_url='http://our_test_domain:8001/oauth2callback')

    client_id = app.title
    client_secret = app.fields['client_secret']
    store_app(environ, app)

    config['oauth.servers']['testserver']['client_id'] = client_id
    config['oauth.servers']['testserver']['client_secret'] = client_secret

    module.client_id = client_id

    initialize_app(config)

    module.http = Http()

# we need a user who is going to use the client app
    user = User('cdent')
    user.set_password('cowpig')
    module.store.put(user)


def test_our_server():
    redirect_uri = get_auth_uri(config, 'testserver')

# confirm the auth uri requires auth
    response, content = http.request(redirect_uri)
    assert response['status'] == '401'

# confirm the auth uri presents a form on GET
    response, content = http.request(redirect_uri,
            method='GET',
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '200', content
    assert '<form' in content
    assert 'action="/_oauth/authorize' in content
    assert 'name="client_id" value="%s"' % client_id in content

# confirm denying in a POST sends error in redirect
    response, content = http.request(redirect_uri + '&deny=',
            method='POST',
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '302'
    location = response['location']

    assert 'error=access_denied' in location

# confirm accepting in a POST redirects with a code
    response, content = http.request(redirect_uri + '&accept=',
            method='POST',
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '302'
    location = response['location']
    assert 'http://our_test_domain:8001/oauth2callback?server_name=testserver&code=' in location
    code = location.rsplit('=', 1)[1]

# use the code to have the consumer ask the provider for an access
# token
    credentials, myhttp = get_credentials(config, 'testserver', code)
    user_info_uri = config['oauth.servers']['testserver']['info_uri']

# use the access token to get some restricted info
    credentials.authorize(myhttp)
    response, content = myhttp.request(user_info_uri)

    assert response['status'] == '200'
    assert '"name": "cdent"' in content
    assert '"roles": []' in content
