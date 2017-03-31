"""

Operations in support of certificate signing and validation

References:
    https://www.ietf.org/rfc/rfc4253.txt (esp "6.6.Public Key Algorithms" for key format)
    https://www.ietf.org/rfc/rfc3447.txt (RSASSA-PKCS1-v1_5 for ssh-rsa signing/validation)

"""

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

__all__ = [
    "certificate_signing_methods"
]

#pylint: disable=invalid-name,line-too-long

SSH_CERTIFICATE_DIGESTMETHODS = {
    "ssh-dss": hashes.SHA1(), # per RFC 4253, 6.6. Public Key Algorithms
    "ssh-rsa": hashes.SHA1(),
    "ecdsa-SHA2-nistp256": hashes.SHA256(), # per RFC 5656 6.2.1. Elliptic Curve Digital Signature Algorithm
    "ecdsa-SHA2-nistp384": hashes.SHA384(), # per RFC 5656 6.2.1. Elliptic Curve Digital Signature Algorithm
    "ecdsa-SHA2-nistp521": hashes.SHA512(), # per RFC 5656 6.2.1. Elliptic Curve Digital Signature Algorithm
    "ssh-ed25519": hashes.SHA512(), # per draft-josefsson-eddsa-ed25519-03 5.6. Sign pp 2
}

def sign_rsa(data, private_key):
    """
    Sign the data in accordance with the 'ssh-rsa' key type, per
    RFC 4253, 6.6. Public Key Algorithms
    """
    return {
        "r": private_key.sign(
            data,
            padding.PKCS1v15,
            SSH_CERTIFICATE_DIGESTMETHODS['ssh-rsa']
        )
    }

def sign_dss(data, private_key):
    """
    Sign the data in accordance with the 'ssh-rsa' key type, per
    RFC 4253, 6.6. Public Key Algorithms
    """
    raw_signature = decode_dss_signature(
        private_key.sign(
            data,
            SSH_CERTIFICATE_DIGESTMETHODS['ssh-dss']
        )
    )
    return {"r": raw_signature[0], "s": raw_signature[1]}

certificate_signing_methods = {
    "ssh-dss": sign_dss,
    "ssh-rsa": sign_rsa,
}
