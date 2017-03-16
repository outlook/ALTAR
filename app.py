"""
Generate an SSH certificate using AAD information
"""

#pylint: disable=import-error,old-style-class,no-init,no-self-use

from pprint import pformat as pf
import os
import web
import requests
import adal

TENANT_ID = os.environ.get(
    'WEBSITE_AUTH_OPENID_ISSUER',
    'https://sts.microsoft.com/common/').split('/', 4)[3]
APPLICATION_ID = os.environ.get('WEBSITE_AUTH_CLIENT_ID', '00000002-0000-0000-c000-000000000000')

URLS = (
    '/.*', 'SSHCertGenerator'
)
WSGI_APP = web.application(URLS, globals()).wsgifunc()

def get_groups(access_token, prefix_filter=None):
    """ Return a list of the user's groups' displayNames. """

    headers = {
        "Authorization": "Bearer {}".format(access_token),
        "Content-Type": "application/json"
    }
    group_url = "https://graph.windows.net/me/memberOf?api-version=1.6"

    groups = []
    while True:
        try:
            resp = requests.get(
                group_url,
                headers=headers
            )
            resp.encoding = 'utf-8-sig'
            data = resp.json()
        except Exception as err: #pylint: disable=broad-except
            raise web.HTTPError('503 Service Unavailable', data=str(err))

        if 'odata.error' in data:
            raise web.HTTPError(
                '503 Service Unavailable',
                data="odata error: {}".format(data['odata.error'])
            )

        if 'value' not in data:
            raise web.HTTPError(
                '503 Service Unavailable',
                data="no value in group data {}".format(data)
            )
        for value in data['value']:
            try:
                if prefix_filter is None \
                        or (prefix_filter is not None and value['displayName'].startswith(prefix_filter)):
                    groups.append(value['displayName'])
            except KeyError as err:
                # log an error here eventually
                pass

        if 'odata.nextLink' in data:
            group_url = "https://graph.windows.net/{tenant}/{link}&api-version=1.6".format(
                tenant=TENANT_ID,
                link=data['odata.nextLink']
            )
        else:
            break

    return groups

class SSHCertGenerator(object):         #pylint: disable=missing-docstring,too-few-public-methods
    def GET(self):                      #pylint: disable=invalid-name
        """ GET method takes no arguments. Returns a base64-encoded cert in a json obj """

        adal_ctx = adal.AuthenticationContext(
            "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47"
        )
        aad_refresh_token = web.ctx.env.get('HTTP_X_MS_TOKEN_AAD_REFRESH_TOKEN')
        #aad_id_token = web.ctx.env.get('HTTP_X_MS_TOKEN_AAD_ID_TOKEN')

        graph_token_info = adal_ctx.acquire_token_with_refresh_token(
            aad_refresh_token,
            APPLICATION_ID,
            'https://graph.windows.net'
        )
        graph_bearer_token = graph_token_info['accessToken']
        user_info = requests.get(
            'https://graph.windows.net/me?api-version=1.6',
            headers={"Authorization": "Bearer {}".format(graph_bearer_token)},
            data={}
        ).json()
        user_name = user_info['userPrincipalName'].split('@')[0]
        group_list = get_groups(graph_bearer_token, prefix_filter='olm-')
        return """Hello, {name}, you gave me
        {env}
        with which I got
        {reftok},
        which told me you belong to
        {groupinfo}""".format(
            name=user_name,
            env=pf(aad_refresh_token),
            reftok=pf(graph_bearer_token),
            groupinfo=pf(group_list)
        )

if __name__ == "__main__":
    web.application(URLS, globals()).run()                      #pylint: disable=no-member
