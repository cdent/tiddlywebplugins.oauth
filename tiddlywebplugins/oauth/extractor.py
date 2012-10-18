"""
A TiddlyWeb credentials extractor that looks for
oauth style bearer tokens and tries to validate
them.
"""

from tiddlyweb.web.extractors import ExtractorInterface

from tiddlywebplugins.oauth.provider import check_access_token


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
            return False

        # XXX do something with scope eventually

        user = self.load_user(environ, candidate_username)
        return {"name": user.usersign, "roles": user.list_roles()}
