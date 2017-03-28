"""
Generate an SSH certificate using AAD information
"""

#pylint: disable=import-error,no-init,no-self-use,invalid-name,missing-docstring,too-few-public-methods

import base64
import json
from pprint import pformat as pf
import os

from azure.common.credentials import ServicePrincipalCredentials
from azure.keyvault import KeyVaultClient
from azure.keyvault.generated.models.key_vault_error import KeyVaultErrorException
from msrest.exceptions import AuthenticationError
import web

from azure_ad import get_groups, get_user_name, get_graph_token
import cert
from cert.encodec import unpack_binstr

TENANT_ID = os.environ['WEBSITE_AUTH_OPENID_ISSUER'].split('/', 4)[3]
CLIENT_ID = os.environ['WEBSITE_AUTH_CLIENT_ID']
CLIENT_SECRET = os.environ['WEBSITE_AUTH_CLIENT_SECRET']

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
    return KeyVaultClient(credentials)

def get_signing_jwk(client):
    # FIXME parameterize the vault URL
    try:
        key_info = client.get_key("https://olm-altar-test.vault.azure.net/keys/signing-key")
    except KeyVaultErrorException as err:
        raise RuntimeError("could not get signing key from vault: {}".format(err))
    return key_info

class CAKeyFile(object):
    def GET(self):
        """ Retrieve the signing pubkey out of the vault, and return an OpenSSH CA pubkey file """

        try:
            vault_client = get_vault_client()
            keyinfo = get_signing_jwk(vault_client)
        except AuthenticationError as err:
            raise web.HTTPError(
                "401 Unauthorized",
                data="could not get vault client: {}".format(err)
            )
        except RuntimeError as err:
            raise web.HTTPError(
                '503 Service Unavailable',
                data="client id {} in tenant {} could not get signing key: {}".format(
                    CLIENT_ID,
                    TENANT_ID,
                    err
                )
            )
        key = keyinfo.key                                                           #pylint: disable=no-member
        keyfile = cert.SSHPublicKeyFile()
        try:
            keyfile.e = unpack_binstr(key.e)
            keyfile.n = unpack_binstr(key.n)
        except TypeError:
            raise web.HTTPError(
                "500 Internal Error",
                data="could not decode key from {}".format(pf(key.__dict__))
            )

        encoded_pubkey = base64.b64encode(keyfile.build_keyfile("ssh-rsa"))

        web.header('Content-Type', 'text/plain; charset=UTF-8')
        return "{} {}".format(
            'ssh-rsa',
            encoded_pubkey,
        )


class SSHCertGenerator(object):
    def POST(self):
        """ GET method takes no arguments. Returns a base64-encoded cert in a json obj """

        aad_refresh_token = web.ctx.env.get('HTTP_X_MS_TOKEN_AAD_REFRESH_TOKEN')
        graph_bearer_token = get_graph_token(CLIENT_ID, TENANT_ID, aad_refresh_token)

        vault_client = get_vault_client()
        signing_jwk = get_signing_jwk(vault_client).key                             #pylint: disable=no-member

        user_name = get_user_name(graph_bearer_token)
        try:
            groups = get_groups(TENANT_ID, graph_bearer_token, prefix_filter='olm-')
        except RuntimeError as err:
            raise web.HTTPError('503 Service Unavailable', data=str(err))

        post_data = json.loads(web.data())
        if 'pubkey' not in post_data:
            raise web.HTTPError('400 Bad Request', data="could not find pubkey")
        # TODO validate pubkey format?
        # TODO require the entire request be signed (header?) and validate it

        signing_key = cert.SSHPublicKeyFile()
        signing_key.e = signing_jwk.e
        signing_key.n = signing_jwk.n

        user_cert = cert.SSHCertificate(
            user_id=user_name.split('@')[0],
            key_id=user_name,
            pubkey=post_data['pubkey'],
            cert_type=cert.SSH_CERT_TYPE_USER,
            signature_key=signing_key.build_keyfile("ssh-rsa")
        )
        unsigned_cert = user_cert.build_certificate("ssh-rsa-cert-v01@openssh.com")

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
