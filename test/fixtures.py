"""
Fixtures for tests.
"""

from wsgi_intercept import httplib2_intercept
import wsgi_intercept
from tiddlyweb.web.serve import load_app

import shutil

def initialize_app(config, domain='our_test_domain', port=8001):
    """
    Setup a wsgi intercepted server.
    """
    config['server_host'] = {
            'scheme': 'http',
            'host': domain,
            'port': str(port),
            }
    app = load_app()
    def app_fn():
        return app
    
    httplib2_intercept.install()
    wsgi_intercept.add_wsgi_intercept(domain, port, app_fn)

def clean_store():
    try:
        shutil.rmtree('store')
    except:
        pass
