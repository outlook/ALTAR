"""

Certificate formats, as specified in the OpenSSH documentation
file 'PROTOCOL.certkeys'

http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.10

Not implemented:
 * ssh-dss-cert-v01
 * ecdsa-sha2-nistp256-v01
 * ecdsa-sha2-nistp384-v01
 * ecdsa-sha2-nistp521-v01

"""

from .encodec import mpint, packedlist, string, uint32, uint64

#pylint: disable=bad-whitespace

RSA_FORMAT = [
    (string, "nonce"),
    (mpint,  "e"),
    (mpint,  "n"),
    (uint64, "serial"),
    (uint32, "type"),
    (string, "key_id"),
    (string, "valid_principals"),
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
    (uint32, "cert_type"),
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

ssh_pubkey_formats = {
    "ssh-rsa": RSA_PUBKEY,
    "ssh-ed25519": ED25519_PUBKEY,
}

__all__ = ["ssh_certificate_formats"]
