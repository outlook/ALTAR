#!/usr/bin/env python
"""
Do things
"""
from __future__ import print_function

import argparse
import os
import sys

import adal
from cert.request import SSHCSR
from cert.pubkey import SSHPublicKeyFile
import requests

#pylint: disable=missing-docstring

class EnvDefault(argparse.Action):                                          #pylint: disable=too-few-public-methods
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if not default and envvar:
            if envvar in os.environ:
                default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)

def get_token(token_cache_file, authority_url, client_id, resource_url, user_id):
    try:
        with open(token_cache_file, "r+") as token_cache_fh:
            token_cache = adal.TokenCache(state=token_cache_fh.read())
    except IOError:
        print("no token cache found")
        with open(token_cache_file, "w+") as _:
            token_cache = adal.TokenCache(state="")
    context = adal.AuthenticationContext(authority_url, cache=token_cache)

    try:
        token = context.acquire_token(
            resource_url,
            user_id,
            client_id
        )
    except adal.adal_error.AdalError:
        token = None
    if token is None:
        print("No cached credentials")
        code = context.acquire_user_code(resource_url, client_id)
        print(code["message"])
        try:
            token = context.acquire_token_with_device_code(
                resource=resource_url,
                user_code_info=code,
                client_id=client_id
            )
        except KeyboardInterrupt:
            print("Cancelling code request")
            context.cancel_request_to_get_token_with_device_code(code)
            sys.exit(1)
        with open(token_cache_file, "w+") as token_cache_fh:
            token_cache_fh.write(token_cache.serialize())
    return token

def parse_args():
    parser = argparse.ArgumentParser("altar")
    parser.add_argument('-s', '--appid', metavar='AZURE_APP_ID', action=EnvDefault,
                        envvar='AZURE_APP_ID', required=True,
                        help="ALTAR CLI Azure AD App ID (GUID)")

    parser.add_argument('-e', '--tenant', metavar='AZURE_TENANT_ID', action=EnvDefault,
                        envvar='AZURE_TENANT_ID', required=True,
                        help="ALTAR CLI Azure AD Tenant ID")

    parser.add_argument('-u', '--url', metavar='ALTAR_URL', action=EnvDefault,
                        envvar='ALTAR_URL', required=True,
                        help='ALTAR Web Service endpoint URL')

    parser.add_argument('-t', '--tokencache', metavar='CACHE_FILE', action=EnvDefault,
                        envvar='CACHE_FILE', default=".tokencache",
                        help="File to cache Azure authentication tokens")

    parser.add_argument('-p', '--principal', metavar='ALTAR_PRINCIPAL_ID', action=EnvDefault,
                        envvar='ALTAR_PRINCIPAL_ID', required=False, help="Certificate principal")

    parser.add_argument('-c', '--host-certificate', action='store_true',
                        help="Request host certificate (defaults to user)")

    parser.add_argument('-l', '--login', metavar='AZURE_USERID', action=EnvDefault,
                        envvar='AZURE_USERID', required=True,
                        help="Azure AD User ID for authentication")

    parser.add_argument('-a', '--ssh-agent', metavar='SSH_AUTH_SOCK', action=EnvDefault,
                        envvar='SSH_AUTH_SOCK', required=False, help="ssh-agent socket file")

    parser.add_argument('-i', '--identity', metavar='IDENTITY', action=EnvDefault,
                        envvar='IDENTITY', required=True, help="SSH private key file")

    parser.add_argument('--cakey', action='store_true',
                        help="Get the ALTAR CA public key")

    return parser.parse_args()


def main():
    options = parse_args()
    authority_url = "https://login.microsoftonline.com/{}".format(options.tenant)
    try:
        token = get_token(
            options.tokencache,
            authority_url,
            options.appid,
            options.url,
            options.login
        )
    except adal.adal_error.AdalError as err:
        print("Could not authenticate: {}".format(err))
        sys.exit(1)

    with open(os.path.expanduser(options.identity)) as privkey_fh:
        privkey = privkey_fh.read()
    pubkey = SSHPublicKeyFile.load(os.path.expanduser(options.identity + ".pub"))

    cert_principal = options.principal if options.principal else options.login
    csr = SSHCSR(
        principal=cert_principal,
        certificate_type="user" if not options.host_certificate else "host",
        certificate_format="ssh-rsa-cert-v01@openssh.com",
        public_key=pubkey,
        critical_options={},
        extensions=["permit-pty"]
    )
    csr.sign(privkey)

    response = requests.post(
        options.url+"/cert",
        headers={"Authorization": "Bearer {}".format(token['accessToken'])},
        data=csr.json(include_signature=True)
    )
    if response.status_code >= 300:
        with open("error.html", "w+") as errfile:
            errfile.write(response.text)
            print('The operation failed. Please see error.html for details')
            sys.exit(1)
    else:
        certfilename = os.path.expanduser(options.identity + "-cert.pub")
        with open(certfilename, "w") as certfile:
            certfile.write(response.text)
            print("Wrote certificate file to {}".format(certfilename))


if __name__ == "__main__":
    main()
