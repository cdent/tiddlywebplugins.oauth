"""
A handler that providers information about the current user,
which can be used by a consumer to gather an authentic user
id from a provider.
"""


import json


from tiddlywebplugins.utils import require_any_user


@require_any_user()
def user_info(environ, start_response):
    """
    Simple handler which displays the current user's
    username and roles.

    Provides a way for a provider to, uh, provide an
    authentic bit of user info.
    """
    current_user = environ['tiddlyweb.usersign']
    json_data = json.dumps(current_user)
    start_response('200 OK', [
        ('Content-Type', 'application/json; charset=UTF-8')])
    return [json_data]
