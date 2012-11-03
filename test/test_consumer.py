"""
Test a consumer (for the effect of user registration and
auth). To do this we need:

* A provider.
* A user that exists on that provider.
* A client app (consumer) of the provider.
* A user-agent that wants to auth on the consumer with their identity
  on the provider.

The primary purpose of this is to cover the consumer code, but in
the process it ought to illuminate the entire structure. This is
only possible now that provider code has been written: the existing
consumer code was tested on a live server, which is a bit lame, but
was needed to help understand wtf is going on.
"""

from base64 import b64encode
from urllib import urlencode

from tiddlyweb.config import config
from tiddlyweb.model.user import User
from tiddlywebplugins.utils import get_store

from tiddlywebplugins.oauth import ensure_bags
from tiddlywebplugins.oauth.client import create, store_app

from httplib2 import Http, RedirectLimit

from test.fixtures import initialize_app, clean_store

authorization = b64encode('cdent:cowpig')


def setup_module(module):
    """
    clean up the store, establish a registered client
    """
    clean_store()
    module.store = get_store(config)
    environ = {'tiddlyweb.config': config, 'tiddlyweb.store': module.store}
    ensure_bags(config)

    # make an application and store that info
    app = create(name='testapp', owner='appowner1',
            app_url='http://our_test_domain:8001',
            callback_url='http://our_test_domain:8001/_oauth/callback')

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


def test_auth_via_consumer():
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/callback')

    assert response['status'] == '400'
    assert 'server_name required' in content

    try:
        response, content = http.request(
                'http://our_test_domain:8001/_oauth/callback?server_name=testserver',
                redirections=0)
    except RedirectLimit, exc:
        response = exc.response

    # We've been sent to cookie form, confirm.
    assert response['status'] == '302'
    assert '_oauth/authorize' in response['location']

    authorize_uri = response['location']

    response, content = http.request(authorize_uri,
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '200'
    assert '<form action="/_oauth/authorize" method="POST">' in content

    # no client present
    post_hash = dict(
        name='testapp',
        access_type='offline',
        redirect_uri='http://our_test_domain:8001/_oauth/callback?server_name=testserver',
        response_type='code',
        scope='',
        accept='accept')

    post_data = urlencode(post_hash)

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'error=unauthorized_client' in response['location']

    post_hash['client_id'] = 'frankly wrong'
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'error=unauthorized_client' in response['location']

    post_hash['client_id'] = client_id
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'code=' in response['location']

    response, content = http.request(response['location'])

    assert response['status'] == '200'

    assert 'code: ' in content
    assert 'credentials: ' in content
    assert '{"name": "cdent", "roles": []}' in content

    del post_hash['redirect_uri']
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'code=' in response['location']

    post_hash['redirect_uri'] = 'http://our_test_domain:8001/bad/uri'
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'error=invalid_request' in response['location']

    del post_hash['redirect_uri']
    post_hash['state'] = 'the secret is here'
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)

    assert response['status'] == '302'
    assert 'code=' in response['location']
    assert 'state=the%20secret%20is%20here' in response['location']

    del post_hash['response_type']
    post_data = urlencode(post_hash)
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/authorize',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            method='POST',
            body=post_data)
    assert response['status'] == '302'
    assert 'error=invalid_request' in response['location']
