"""
Generate an SSH certificate using AAD information
"""

#pylint: disable=import-error,no-init,no-self-use,invalid-name,missing-docstring,too-few-public-methods

import base64
import json
from pprint import pformat as pf
import os

from msrest.exceptions import AuthenticationError
import web

from azure_ad import get_groups, get_user_name, get_graph_token
from azure_keyvault import get_vault_client, get_signing_pubkey, get_signing_privkey
import cert
from cert.request import SSHCSR

TENANT_ID = os.environ['WEBSITE_AUTH_OPENID_ISSUER'].split('/', 4)[3]
CLIENT_ID = os.environ['WEBSITE_AUTH_CLIENT_ID']
CLIENT_SECRET = os.environ['WEBSITE_AUTH_CLIENT_SECRET']

URLS = (
    '/pubkey', 'CAKeyFile',
    '/cert', 'SSHCertGenerator'
)
WSGI_APP = web.application(URLS, globals()).wsgifunc()


class CAKeyFile(object):
    def GET(self):
        """ Retrieve the signing pubkey out of the vault, and return an OpenSSH CA pubkey file """

        try:
            vault_client = get_vault_client(CLIENT_ID, CLIENT_SECRET, TENANT_ID)
            pubkey_numbers = get_signing_pubkey(
                vault_client,
                "https://olm-altar-test.vault.azure.net/secrets/signing-key.pub"
            ).public_numbers()
        except AuthenticationError as err:
            raise web.HTTPError(
                "401 Unauthorized",
                data="could not get vault client: {}".format(err)
            )
        except RuntimeError as err:
            raise web.HTTPError(
                '503 Service Unavailable',
                data="could not get signing key: {}".format(err)
            )

        # Yes, this is redundant (since we just store the openssh-encoded public key as a vault
        #  secret directly), but it illustrates how to operate when we instead call get_signing_jwk
        #  to get values from a Key Vault key.
        keyfile = cert.SSHPublicKeyFile("ssh-rsa")
        try:
            keyfile.e = pubkey_numbers.e
            keyfile.n = pubkey_numbers.n
        except TypeError:
            raise web.HTTPError(
                "500 Internal Error",
                data="could not decode key from {}".format(pf(keyfile.__dict__))
            )

        encoded_pubkey = base64.b64encode(keyfile.build_keyfile())

        web.header('Content-Type', 'text/plain; charset=UTF-8')
        return "{} {} {}".format(
            'ssh-rsa',
            encoded_pubkey,
            "ALTAR OpenSSH CA"
        )


class SSHCertGenerator(object):
    def POST(self):
        """

        Accepts a cert.request.CSR_PROTOTYPE-alike JSON object, validates its signature,
        constructs a new certificate, and signs it.

        """

        graph_bearer_token = get_graph_token(
            CLIENT_ID,
            TENANT_ID,
            web.ctx.env.get('HTTP_X_MS_TOKEN_AAD_REFRESH_TOKEN')
        )

        try:
            user_name = get_user_name(graph_bearer_token)
            _groups = get_groups(TENANT_ID, graph_bearer_token, prefix_filter='olm-')
            csr = cert.SSHCSR.load(json.loads(web.data()))
        except RuntimeError as err:
            raise web.HTTPError('503 Service Unavailable', data=str(err))
        except ValueError as err:
            raise web.HTTPError('400 Bad Request', data=err)

        if not csr.verify():
            raise web.HTTPError('403 Forbidden', data="bad request signature")
        if csr.principal != user_name.split('@')[0]:
            raise web.HTTPError('403 Forbidden', data="csr principal not valid")


        vault_client = get_vault_client(CLIENT_ID, CLIENT_SECRET, TENANT_ID)
        signing_key = get_signing_privkey(
            vault_client,
            "https://olm-altar-test.vault.azure.net/secrets/signing-key"
        )
        pubkey_numbers = signing_key.public_key().public_number()
        signing_pubkey = cert.SSHPublicKeyFile("ssh-rsa")
        signing_pubkey.e = pubkey_numbers.e
        signing_pubkey.n = pubkey_numbers.n

        user_cert = cert.SSHCertificate(csr.certificate_format)
        for number, value in csr.public_key.__dict__.items():
            user_cert.__setattr__(number, value)
        user_cert.type = SSHCSR.CSR_CERTIFICATE_TYPES[csr.certificate_type]
        user_cert.key_id = "{}_{}".format(csr.certificate_type, csr.principal)
        user_cert.valid_principals = [user_name.split('@')[0]]
        user_cert.critical_options = csr.critical_options
        user_cert.extensions = csr.extensions
        user_cert.signature_key = signing_pubkey.build_keyfile()

        user_cert.signature = user_cert.sign(signing_key)

        return "{} {} {}".format(
            user_cert.certificate_format,
            base64.b64encode(user_cert.build_certificate()),
            user_name
        )

if __name__ == "__main__":
    web.application(URLS, globals()).run()                      #pylint: disable=no-member
