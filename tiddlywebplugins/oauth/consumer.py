"""
Routines used by the oAuth2 client, aka the consumer.

For now this module hosts a client callback that was
created for the express purpose of allowing new user
registration in TiddlyWeb, using auth info from a 
remote service such as Facebook, Github, Google.

As such, it extends the generic purpose of the
callback uri beyond what it would normally be.

A more generic tool would simply store the code
for future requests. So, for the future these
two purposes need to be separated.
"""

from httpexceptor import HTTP302, HTTP400

from .auth import get_auth_uri, get_credentials


def do_user_auth(environ, start_response):
    """
    Consumer authorization for the sake of a user.

    If no `code` is present then we send the user to the
    auth uri of the selected provider. If there is a code
    then we use that to get an access token, then use that
    access token to get some information about the user
    at the provider.

    XXX: Save the access token for later use.
    """

    query = environ['tiddlyweb.query']
    config = environ['tiddlyweb.config']

    code = query.get('code', [None])[0]
    error = query.get('error', [None])[0]
    server_name = query.get('server_name', [None])[0]

    if not server_name:
        raise HTTP400('invalid request, server_name required')

    # initial redirect
    if not code and not error:
        raise HTTP302(get_auth_uri(config, server_name))

    output = []
    if code:
        output.append('code: %s\n' % code)
        credentials, http = get_credentials(config, server_name, code)
        output.append('credentials: %s\n' % credentials)
        credentials.authorize(http)
        response, content = http.request(
                config['oauth.servers'][server_name]['info_uri'])
        if response['status'] == '200':
            output.append(content)
        else:
            output.append('Unable to reach info_uri')

    if error:
        output.append('error: %s\n' % error)

    start_response('200 OK', [('Content-Type', 'text-plain')])
    return output
