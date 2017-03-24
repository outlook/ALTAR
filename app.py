"""
Generate an SSH certificate using AAD information
"""

#pylint: disable=import-error,no-init,no-self-use,invalid-name,missing-docstring,too-few-public-methods

from pprint import pformat as pf
import os

from azure.common.credentials import ServicePrincipalCredentials
import web

from azure_ad import get_groups, get_user_name, get_graph_token
#import cert

TENANT_ID = os.environ.get(
    'WEBSITE_AUTH_OPENID_ISSUER',
    'https://sts.microsoft.com/common/').split('/', 4)[3]
CLIENT_ID = os.environ.get('WEBSITE_AUTH_CLIENT_ID', '00000002-0000-0000-c000-000000000000')
CLIENT_SECRET = os.environ.get('WEBSITE_AUTH_CLIENT_SECRET', '')

URLS = (
    '/cakey', 'CAKeyFile',
    '/.*', 'SSHCertGenerator'
)
WSGI_APP = web.application(URLS, globals()).wsgifunc()

def get_vault_client():
    """ Get a KeyVault client belonging to this application """
    credentials = ServicePrincipalCredentials(
        client_id=CLIENT_ID,
        secret=CLIENT_SECRET,
        tenant=TENANT_ID,
        resource="https://vault.azure.net"
    )
    return azure.keyvault.KeyVaultClient(credentials)

class CAKeyFile(object):
    def GET(self):
        """ Retrieve the signing pubkey out of the vault, and return an OpenSSH CA pubkey file """
        vault_client = get_vault_client()
        key_info = vault_client.get_key("https://olm-altar-test.vault.azure.net/keys/signing-key")
        return "Thank you for shooping at foomart, Mr. {}".format(key_info)


class SSHCertGenerator(object):
    def GET(self):
        """ GET method takes no arguments. Returns a base64-encoded cert in a json obj """

        aad_refresh_token = web.ctx.env.get('HTTP_X_MS_TOKEN_AAD_REFRESH_TOKEN')
        graph_bearer_token = get_graph_token(CLIENT_ID, TENANT_ID, aad_refresh_token)
        #keyvault_client = get_vault_client()

        user_name = get_user_name(graph_bearer_token)
        try:
            groups = get_groups(TENANT_ID, graph_bearer_token, prefix_filter='olm-')
        except RuntimeError as err:
            raise web.HTTPError('503 Service Unavailable', data=str(err))

#        user_cert = cert.SSHCertificate(
#            user_id=user_name.split('@')[0],
#            key_id=user_name,
#            pubkey="foo"#key from POST?,
#            cert_type=cert.SSH_CERT_TYPE_USER
#        )
#        unsigned_cert = cert.build_certificate()
#
        return """Hello, {name}, you gave me
        {env}
        with which I got
        {reftok},
        which told me you belong to
        {groupinfo}""".format(
            name=user_name,
            env=pf(aad_refresh_token),
            reftok=pf(graph_bearer_token),
            groupinfo=pf(groups)
        )

if __name__ == "__main__":
    web.application(URLS, globals()).run()                      #pylint: disable=no-member
