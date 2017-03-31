"""

Helper functions to retrieve things from an Azure Key Vault.

Will eventually include helpers for signing operations, once KV supports EC (or adds
support for SHA-1, in the case of ssh-rsa).
"""

from azure.common.credentials import ServicePrincipalCredentials
from azure.keyvault import KeyVaultClient
from azure.keyvault.generated.models.key_vault_error import KeyVaultErrorException

from cryptography import exceptions as cryptography_exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_pem_private_key

def get_vault_client(client_id, client_secret, tenant_id):
    """ Get a KeyVault client belonging to this application """
    credentials = ServicePrincipalCredentials(
        client_id=client_id,
        secret=client_secret,
        tenant=tenant_id,
        resource="https://vault.azure.net"
    )
    return KeyVaultClient(credentials)


def get_signing_privkey(client, secret_url):
    """
    Gets a PEM file from the vault, and returns one of RSAPrivateKey, DSAPrivateKey, or
    EllipticCurvePrivateKey depending on the contents of the secret.
    """
    try:
        raw_privkey = client.get_secret(secret_url).value
        return load_pem_private_key(
            str(raw_privkey),
            None,
            default_backend()
        )
    except KeyVaultErrorException as err:
        raise RuntimeError("could not get signing key private numbers from vault: {}".format(err))
    except ValueError as err:
        raise RuntimeError("could not load private key from vault: {}".format(err))
    except cryptography_exceptions.UnsupportedAlgorithm as err:
        raise RuntimeError("key in vault is not a supported type: {}".format(err))

def get_signing_pubkey(client, secret_url):
    """
    Gets a PEM file from the vault, and returns one of RSAPublicKey, DSAPublicKey, or
    EllipticCurvePublicKey depending on the contents of the secret.
    """
    try:
        raw_pubkey = client.get_secret(secret_url).value
        return load_ssh_public_key(
            str(raw_pubkey),
            default_backend()
        )
    except KeyVaultErrorException as err:
        raise RuntimeError("could not get signing key public numbers from vault: {}".format(err))
    except ValueError as err:
        raise RuntimeError("could not load public key from vault: {}".format(err))
    except cryptography_exceptions.UnsupportedAlgorithm as err:
        raise RuntimeError("key in vault is not a supported type: {}".format(err))

def get_signing_jwk(client, vault_url):
    """
    Gets a Key from the vault, and returns it in JWT form. As opposed to the other `get*` functions
    above, this does not return a `cryptography` object.

    n.b. values returned in the decoded JWT are packed binary strings. To turn them into ints (for
    packing into mpint, for example), use the encodec.unpack_binstr function.
    """
    try:
        key_info = client.get_key(vault_url)
    except KeyVaultErrorException as err:
        raise RuntimeError("could not get signing key from vault: {}".format(err))
    return key_info
