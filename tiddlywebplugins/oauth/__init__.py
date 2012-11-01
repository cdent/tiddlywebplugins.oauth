"""
Plugin initialization and web handlers for doing oauth.
These need to be split out into differnt files.
"""

from .client import create_app, app_info
from .provider import provider_auth, access_token
from .consumer import do_user_auth
from .user import user_info

from tiddlywebplugins.utils import get_store, ensure_bag


def ensure_bags(config):
    """
    Ensure that our store has the required bags for operations.
    For now this assumes that we're operating on all possible
    consumer/provider dimensions. Bags are cheap, so...
    """
    store = get_store(config)

    # one for storing app info
    app_bag = config.get('oauth.app_bag', 'oauth_apps')
    # one for storing user authorization codes
    token_bag = config.get('oauth.tokens_bag', 'oauth_tokens')
    # one for storing user auth tokens
    registration_bag = config.get('oauth.registrations_bag',
            'oauth_registrations')

    for bag in [app_bag, token_bag, registration_bag]:
        ensure_bag(bag, store, policy_dict=dict(
            read=['NONE'], write=['NONE'], create=['NONE'],
            delete=['NONE'], manage=['NONE']))


def init(config):
    """
    Initialize the plugin by setting handlers and adding
    extractor.
    """
    ensure_bags(config)
    if 'selector' in config:
        config['extractors'].append('tiddlywebplugins.oauth.extractor')
        config['selector'].add('/_oauth/callback', GET=do_user_auth)
        config['selector'].add('/_oauth/createapp', POST=create_app)
        config['selector'].add('/_oauth/appinfo', GET=app_info)
        config['selector'].add('/_oauth/authorize', GET=provider_auth,
                POST=provider_auth)
        config['selector'].add('/_oauth/access_token', POST=access_token)
        config['selector'].add('/_oauth/user_info', GET=user_info)
