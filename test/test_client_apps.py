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

import shutil
import urllib
from base64 import b64encode
from httplib2 import Http
from wsgi_intercept import httplib2_intercept
import wsgi_intercept

from tiddlywebplugins.utils import get_store, ensure_bag
from tiddlywebplugins.oauth.app import create_app, store_app

from tiddlyweb.web.serve import load_app
from tiddlyweb.config import config
from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.model.user import User

authorization = b64encode('cdent:cowpig')

def setup_module(module):
    try:
        shutil.rmtree('store')
    except:
        pass
    module.store = get_store(config)
    config['server_host'] = {
            'scheme': 'http',
            'host': 'our_test_domain',
            'port': '8001',
            }
    module.environ = {'tiddlyweb.config': config,
            'tiddlyweb.store': module.store}
    ensure_bag('oauth_apps', module.store, policy_dict=dict(
        read=['NONE'], write=['NONE'], create=['NONE'],
        delete=['NONE'], manage=['NONE']))
    initialize_app()
    module.http = Http()

    user = User('cdent')
    user.set_password('cowpig')
    module.store.put(user)

def initialize_app():
    app = load_app()
    def app_fn():
        return app
    
    httplib2_intercept.install()
    wsgi_intercept.add_wsgi_intercept('our_test_domain', 8001, app_fn)


def test_create_application():
    app = create_app(name='monkey',
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


def test_web_create_application():
    request_body = urllib.urlencode(dict(name='cow',
            app_url='http://someplace.example.com',
            callback_url='http://however.example.com/callback'))
    response, content = http.request(
            'http://our_test_domain:8001/_oauth/createclient',
            method='POST',
            body=request_body)
    assert response['status'] == '403'

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/createclient',
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic %s' % authorization},
            body=request_body)

    assert response['status'] == '200', content

    assert 'client id:' in content
    assert 'client secret:' not in content

    app_id = content.split(':', 1)[1].strip()

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/clientinfo?app=%s' % app_id,
            method='GET',
            headers={'Authorization': 'Basic %s' % authorization})

    assert response['status'] == '200'
    assert 'client secret:' in content

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/clientinfo',
            method='GET')

    assert response['status'] == '400'

    response, content = http.request(
            'http://our_test_domain:8001/_oauth/clientinfo?app=%s' % '5',
            method='GET')

    assert response['status'] == '404'
