"""

This is a basic type of CSR for OpenSSH certificates

"""

import base64
from collections import OrderedDict
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .cert import CriticalOptions, Extensions, SSHCertificate
from .pubkey import SSHPublicKeyFile

CSR_FIELDS = ['principal', 'criticalOptions', 'extensions', 'certificateType', 'certificateFormat',
              'publicKey', 'signature']

schema_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'request.schema')
with open(schema_file) as schema_fh:
    CSR_SCHEMA = schema_fh.read()

class SSHCSR(object):
    """
    The principal value is the value associated with the user or service principal
    in Azure Active Directory.

    The criticalOptions and extensions keys are required, but may have empty values.

    The certificateType value must be either the string literal "user" or "host".

    The certificateFormat must be the string literal "ssh-rsa-cert-v01@openssh.com".

    The publicKey value should be a base64-encoded public key as output by ssh-keygen (i.e.
    the second field in a public key file, like 'AAAAB3NzaC1yc2EAAAA...". This key must be
    of type "ssh-rsa" and be 2048 bits.

    The signature value is computed over a JSON object as described above up to, and
    including, the public key.

    """
    CSR_CERTIFICATE_TYPES = {
        "host": SSHCertificate.SSH_CERT_TYPE_HOST,
        "user": SSHCertificate.SSH_CERT_TYPE_USER,
    }

    def __init__(self, principal, certificate_type, certificate_format, public_key,     #pylint: disable=too-many-arguments
                 critical_options=None, extensions=None, signature=None):
        self.principal = principal
        self.critical_options = CriticalOptions(
            **{k.replace('-', '_'): v for k, v in (critical_options.items() if critical_options else {})}
        )
        self.extensions = Extensions(**{v.replace('-', '_'): True for v in (extensions if extensions else {})})
        self.certificate_type = certificate_type
        self.certificate_format = certificate_format
        self.public_key = public_key
        self.signature = signature

    def json(self, include_signature):
        """ Return a JSON representation of the CSR """
        out = OrderedDict()
        out["principal"] = self.principal
        out["criticalOptions"] = self.critical_options.dump()
        out["extensions"] = self.extensions.dump()
        out["certificateType"] = self.certificate_type
        out["certificateFormat"] = self.certificate_format
        out["publicKey"] = base64.b64encode(self.public_key.build_keyfile())
        if include_signature:
            out["signature"] = self.signature
        else:
            out["signature"] = ""
        return json.dumps(out)

    def verify(self):
        """ Verify the SSHCSR object in situ """
        public_key = RSAPublicNumbers(self.public_key.e, self.public_key.n)
        try:
            public_key.public_key(default_backend()).verify(
                base64.b64decode(self.signature),
                self.json(False),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def sign(self, private_key):
        """
        Take an OpenSSH RSA2048 private key and sign this SSHCSR, saving the signature.

        private_key is PEM-encoded key material.

        This is, essentially, a JOSE signing operation, but we're DIY'ing for module availability
        reasons.
        """
        private_key = load_pem_private_key(private_key, None, default_backend())
        self.signature = base64.b64encode(private_key.sign(
            self.json(False),
            padding.PKCS1v15(),
            hashes.SHA256()
        ))

    @classmethod
    def load(cls, data):
        """ Load a CSR from a dict (presumably loaded from POSTed JSON) """
        missing_fields = []
        for field in CSR_FIELDS:
            if field not in data:
                missing_fields.append(field)
        if len(missing_fields) > 0:
            raise ValueError("POST data missing fields: {}".format(missing_fields))

        for option in data['criticalOptions']:
            if option not in CriticalOptions.ordered_opts:
                raise ValueError("Unknown criticalOption in request: {}".format(option))

        if data['certificateType'] not in ["user", "host"]:
            raise ValueError("certificateType {} not supported".format(data['certificateType']))

        if data['certificateFormat'] != "ssh-rsa-cert-v01@openssh.com":
            raise ValueError("certificateFormat must be \"ssh-rsa-cert-v01@openssh.com\"")

        print "loaded signature is {}".format(repr(data['signature']))

        newcsr = cls(
            data['principal'],
            data['certificateType'],
            data['certificateFormat'],
            SSHPublicKeyFile.load_b64encoded(data['publicKey']),
            data['criticalOptions'],
            data['extensions'],
            str(data['signature'])
        )
        return newcsr
