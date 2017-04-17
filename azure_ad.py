"""
Helper functions to retrieve and manage the data received from AAD
"""

import adal
import requests

__all__ = [
    "get_groups",
    "get_user_name",
    "get_graph_token",
]


def get_groups(tenant_id, access_token, prefix_filter=None):
    """

    Using the provided access_token, return a list of this user's groups'
    displayName attributes. If prefix_filter is provided, only include the
    groups that begin with that value. If paged results are returned, this
    function will continue making requests until all pages have been obtained.

    """

    headers = {
        "Authorization": "Bearer {}".format(access_token),
        "Content-Type": "application/json"
    }
    group_url = "https://graph.windows.net/me/memberOf?api-version=1.6"

    groups = []
    while True:
        try:
            resp = requests.get(group_url, headers=headers)
            resp.encoding = 'utf-8-sig'
            data = resp.json()
        except Exception as err: #pylint: disable=broad-except
            raise RuntimeError("request to graph API failed: {}".format(str(err)))

        if 'odata.error' in data:
            raise RuntimeError("odata error {}".format(data['odata.error']))

        try:
            for value in data['value']:
                try:
                    if prefix_filter is None \
                            or (prefix_filter is not None \
                                and value['displayName'].startswith(prefix_filter)
                               ):
                        groups.append(value['displayName'])
                except KeyError as err:
                    # log an info msg here eventually; did not find 'displayName'
                    pass
        except KeyError as err:
            raise RuntimeError("no value in group data: {}".format(data))

        if 'odata.nextLink' in data:
            group_url = "https://graph.windows.net/{tenant}/{link}&api-version=1.6".format(
                tenant=tenant_id,
                link=data['odata.nextLink']
            )
        else:
            break

    return groups

def get_user_name(graph_bearer_token):
    """ Get the username of the user who owns the bearer token """
    user_info = requests.get(
        'https://graph.windows.net/me?api-version=1.6',
        headers={"Authorization": "Bearer {}".format(graph_bearer_token)},
        data={}
    ).json()

    return user_info['userPrincipalName']#.split('@')[0]

def get_graph_token(client_id, tenant_id, aad_refresh_token):
    """ Get a bearer token that can be used for the Graph API """
    adal_ctx = adal.AuthenticationContext(
        "https://login.microsoftonline.com/{}".format(tenant_id)
    )

    return adal_ctx.acquire_token_with_refresh_token(
        aad_refresh_token,
        client_id,
        'https://graph.windows.net'
    )['accessToken']
