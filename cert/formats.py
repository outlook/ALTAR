"""

OpenSSH formats, as specified in the OpenSSH documentation.

Certificates
------------

http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.10

Not implemented:
 * ssh-dss-cert-v01
 * ecdsa-sha2-nistp256-v01
 * ecdsa-sha2-nistp384-v01
 * ecdsa-sha2-nistp521-v01

Public Keys
-----------

https://www.ietf.org/rfc/rfc4253.txt sec 6.6 Public Key Algorithms

Not implemented:
 * ssh-dsa
 * ecdsa-sha2-*

"""

from .encodec import mpint, packedlist, string, uint32, uint64

__all__ = ["ssh_certificate_formats", "ssh_pubkey_formats", "ssh_signature_formats"]

#pylint: disable=bad-whitespace,invalid-name

RSA_FORMAT = [
    (string, "nonce"),
    (mpint,  "e"),
    (mpint,  "n"),
    (uint64, "serial"),
    (uint32, "type"),
    (string, "key_id"),
    (packedlist, "valid_principals"),
    (uint64, "valid_after"),
    (uint64, "valid_before"),
    (string, "critical_options"),
    (string, "extensions"),
    (string, "reserved"),
    (string, "signature_key"),
    (string, "signature")
]

ED25519_FORMAT = [
    (string, "nonce"),
    (string, "pubkey"),
    (uint64, "serial"),
    (uint32, "type"),
    (string, "key_id"),
    (packedlist, "valid_principals"),
    (uint64, "valid_after"),
    (uint64, "valid_before"),
    (string, "critical_options"),
    (string, "extensions"),
    (string, "reserved"),
    (string, "signature_key"),
    (string, "signature"),
]

DSS_PUBKEY = [
    (mpint, "p"),
    (mpint, "q"),
    (mpint, "g"),
    (mpint, "y")
]

RSA_PUBKEY = [
    (mpint, "e"),
    (mpint, "n"),
]

ED25519_PUBKEY = [
    (mpint, "pubkey"),
]

ssh_certificate_formats = {
    "ssh-rsa-cert-v01@openssh.com":        RSA_FORMAT,
    #"ssh-dss-cert-v01@openssh.com":        dsa_format,
    #"ecdsa-sha2-nistp256-v01@openssh.com": ecdsa_format,
    #"ecdsa-sha2-nistp384-v01@openssh.com": ecdsa_format,
    #"ecdsa-sha2-nistp521-v01@openssh.com": ecdsa_format,
    "ssh-ed25519-cert-v01@openssh.com":    ED25519_FORMAT,
}

ssh_signature_formats = {
    "ssh-dss":              [(string, "r"), (string, "s")],
    "ssh-rsa":              [(string, "r")],
    "ecdsa-sha2-nistp256":  [(mpint, "r"), (mpint, "s")],
    "ecdsa-sha2-nistp384":  [(mpint, "r"), (mpint, "s")],
    "ecdsa-sha2-nistp521":  [(mpint, "r"), (mpint, "s")],
    "ssh-ed25519":          [(mpint, "R"), (mpint, "S")], # per draft-ietf-curdle-ssh-ed25519-00 6. Signature format
}

ssh_pubkey_formats = {
    "ssh-dss": DSS_PUBKEY,
    "ssh-rsa": RSA_PUBKEY,
    "ssh-ed25519": ED25519_PUBKEY,
}
