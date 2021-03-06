"""
Tests related to the creation and storage of client apps.

Clients have:

    client id:
    name:
    client secret:
    associated owner: (via modifier)
    optional logo:
    app url:
    callback url:

All of these can map to fields on a tiddler, except for id, which comes
from the id.
"""

import urllib
import py.test

from base64 import b64encode
from httplib2 import Http

from tiddlywebplugins.utils import get_store

from tiddlywebplugins.oauth import ensure_bags
from tiddlywebplugins.oauth.client import create, store_app, client_valid

from tiddlyweb.config import config
from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.model.user import User

from test.fixtures import initialize_app, clean_store

authorization = b64encode('cdent:cowpig')


def setup_module(module):
    clean_store()
    module.store = get_store(config)
    module.environ = {'tiddlyweb.config': config,
            'tiddlyweb.store': module.store}
    ensure_bags(config)
    initialize_app(config)
    module.http = Http()

    user = User('cdent')
    user.set_password('cowpig')
    module.store.put(user)


def test_create_application():

    py.test.raises(TypeError, 'create(name="missing")')

    app = create(name='monkey',
            owner='cdent',
            app_url='http://oauth.peermore.com',
            callback_url='http://oauth.peermore.com/oauth2callback')

    assert app.modifier == 'cdent'
    assert app.fields['name'] == 'monkey'
    assert app.fields['app_url'] == 'http://oauth.peermore.com'
    assert (app.fields['callback_url']
            == 'http://oauth.peermore.com/oauth2callback')
    assert 'client_secret' in app.fields

    assert isinstance(app, Tiddler)

    app = store_app(environ, app)

    assert client_valid(environ, app.title, app.fields['client_secret'])


def test_web_create_application():
    request_body = urllib.urlencode(dict(name='cow',
            app_url='http://someplace.example.com',
            logo='http://someplace.example.com/picture.png',
            callback_url='http://however.example.com/callback'))
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/createapp',
            method='POST',
            body=request_body)
    assert response['status'] == '403'

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/createapp',
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            body=request_body)

    assert response['status'] == '200', content

    assert 'client id:' in content
    assert 'client secret:' not in content

    app_id = content.split(':', 1)[1].strip()

    request_body = urllib.urlencode(dict(
            app_url='http://someplace.example.com',
            callback_url='http://however.example.com/callback'))

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/createapp',
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            body=request_body)

    assert response['status'] == '400'
    assert 'Invalid form submission' in content

    # get app info
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/appinfo?app=%s' % app_id,
            method='GET',
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '200'
    assert 'client secret:' in content

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/appinfo',
            method='GET')

    assert response['status'] == '400'

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/appinfo?app=%s' % '5',
            method='GET')

    assert response['status'] == '404'
