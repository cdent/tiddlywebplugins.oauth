config = {
        'system_plugins': ['tiddlywebplugins.oauth'],
        'log_level': 'DEBUG',
        'oauth.servers': {
            'testserver': {
                'scope': [],
                'auth_uri': 'http://our_test_domain:8001/_oauth/authorize',
                'token_uri': 'http://our_test_domain:8001/_oauth/access_token',
                'redirect_uri': 'http://our_test_domain:8001/_oauth/callback',
                'info_uri': 'http://our_test_domain:8001/_oauth/user_info',
            }
        }
}
