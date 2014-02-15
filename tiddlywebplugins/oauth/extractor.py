"""
A TiddlyWeb credentials extractor that looks for
oauth style bearer tokens and tries to validate
them.
"""

from httpextractor import HTTP401

from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.store import StoreError
from tiddlyweb.web.extractors import ExtractorInterface


class Extractor(ExtractorInterface):
    """
    Look at the Authorization header for a token that
    looks like it might be oauth-ish and attempt to
    validate it.
    """

    def extract(self, environ, start_response):
        user_info = environ.get('HTTP_AUTHORIZATION', None)
        if user_info is None:
            return False

        if user_info.lower().startswith('bearer'):
            token = user_info.strip().split(' ')[1]
        else:
            return False

        # We have a token that might be oauth stuff,
        # so let's give it a go.
        candidate_username, scope = check_access_token(environ, token)

        if not candidate_username:
            raise HTTP401('Bearer error="invalid token")

        # XXX do something with scope eventually

        user = self.load_user(environ, candidate_username)
        return {"name": user.usersign, "roles": user.list_roles()}


def check_access_token(environ, token):
    """
    Extract a user from token information, if the token is valid.
    """
    config = environ['tiddlyweb.config']
    store = environ['tiddlyweb.store']
    bag_name = config.get('oauth.tokens_bag', 'oauth_tokens')

    token_info = Tiddler(token, bag_name)
    try:
        token_info = store.get(token_info)
    except StoreError:
        return None, None

    token_type = token_info.fields['token_type']
    expires_in = token_info.fields.get('expires_in', None)

    client_id = token_info.fields['client']
    # XXX verify that client_id is "us"

    if token_type != 'bearer':
        return None, None
    user = token_info.modifier
    if 'scope' in token_info.fields:
        scope = token_info.fields['scope'].split(' ')
    else:
        scope = ''

    if expires_in:
        # XXX check against token creation time delete if expired
        pass

    return user, scope
