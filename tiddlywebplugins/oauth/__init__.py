"""
Plugin initialization and web handlers for doing oauth.
These need to be split out into differnt files.
"""

from .client import create_app, app_info
from .provider import provider_auth, access_token
from .consumer import do_user_auth
from .user import user_info


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
