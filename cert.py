"""

Build OpenSSH certificates erryday.

"""

import calendar
from datetime import datetime, timedelta
import math
from random import getrandbits
from struct import pack, unpack, error as struct_error

SSH_CERT_TYPE_USER = 1
SSH_CERT_TYPE_HOST = 2

#pylint: disable=missing-docstring

def encode_uint32(value):
    if value > 2**32 -1:
        raise ValueError("cannot pack {} into uint32".format(value))
    return pack("!I", value)

def decode_uint32(value):
    return unpack('!I', value[:4])[0], value[4:]

def encode_uint64(value):
    if value > 2**64 - 1:
        raise ValueError("cannot pack {} into uint64".format(value))
    return pack("!Q", value)

def decode_uint64(value):
    return unpack('>Q', value[:8])[0], value[8:]

def encode_string(value):
    if len(value) > 2**32 - 1:
        raise ValueError("Cannot pack a string longer than 4 GiB")
    try:
        return pack("!I{l}s".format(l=len(value)), len(value), value)
    except struct_error as err:
        raise ValueError("could not pack value {}: {}".format(repr(value), err))

def decode_string(value):
    size = unpack('>I', value[:4])[0]+4
    return value[4:size], value[size:]

def encode_list(value):
    return encode_string(''.join([encode_string(v) for v in value]))

def decode_list(value):
    joined, remaining = decode_string(value)
    encoded_list = []
    while len(joined) > 0:
        try:
            elem, joined = decode_string(joined)
        except struct_error as err:
            raise ValueError("could not decode list element value {}".format(repr(joined)))
        encoded_list.append(elem)
    return encoded_list, remaining

class CriticalOptions(object): #pylint: disable=too-few-public-methods
    ordered_opts = ['force-command', 'source-addresses']

    def __init__(self, force_command=None, source_addresses=None):
        self.force_command = force_command
        self.source_addresses = source_addresses

    def render(self):
        output = ""
        for opt in CriticalOptions.ordered_opts:
            value = self.__getattribute__(opt.replace("-", "_"))
            if value:
                output += encode_string(opt) + encode_string(value)
        return output

    @classmethod
    def parse(cls, encoded_list):
        parsed_opts = {}
        while encoded_list:
            option, remains = decode_string(encoded_list)
            value, encoded_list = decode_string(remains)
            option = option.replace("-", "_")
            parsed_opts[option] = value
        return cls(**parsed_opts)

class Extensions(object): #pylint: disable=too-few-public-methods
    ordered_exts = ['permit-X11-forwarding', 'permit-agent-forwarding',
                    'permit-port-forwarding', 'permit-pty', 'permit-user-rc']

    def __init__(self, permit_X11_forwarding=False, permit_agent_forwarding=False,  #pylint: disable=too-many-arguments
                 permit_port_forwarding=False, permit_pty=False, permit_user_rc=False):
        self.permit_X11_forwarding = permit_X11_forwarding
        self.permit_agent_forwarding = permit_agent_forwarding
        self.permit_port_forwarding = permit_port_forwarding
        self.permit_pty = permit_pty
        self.permit_user_rc = permit_user_rc

    def render(self):
        output = ""
        for ext in Extensions.ordered_exts:
            enabled = self.__getattribute__(ext.replace("-", "_"))
            if enabled:
                output += encode_string(ext) + encode_string("")
        return output

    @classmethod
    def parse(cls, encoded_list):
        parsed_exts = {}
        while encoded_list:
            extension, empty = decode_string(encoded_list)
            _, encoded_list = decode_string(empty)
            extension = extension.replace('-', '_')
            parsed_exts[extension] = True
        return cls(**parsed_exts)



class CertificateBuilder(object): #pylint: disable=too-many-instance-attributes

    ed25519_format = [
        ("string", "nonce"),
        ("string", "pubkey"),
        ("uint64", "serial"),
        ("uint32", "cert_type"),
        ("string", "key_id"),
        ("list",   "valid_principals"),  #pylint: disable=bad-whitespace
        ("uint64", "valid_after"),
        ("uint64", "valid_before"),
        ("string", "critical_options"),
        ("string", "extensions"),
        ("string", "reserved"),
        ("string", "signature_key"),
        ("string", "signature"),
    ]

    def __init__(self, user_id=None, key_id=None, pubkey=None, cert_type=None, hours_valid=3,
                 crit_opts=None, exts=None):
        self.key_id = key_id
        self.valid_principals = [user_id] if user_id else None
        self._pubkey = pubkey
        self._cert_type = cert_type
        self._critical_options = crit_opts
        self._extensions = exts
        self.nonce = str(bytearray(getrandbits(8) for _ in range(32)))

        self.hours_valid = hours_valid

    @property
    def pubkey(self):
        """ String-encode and return the public key """
        if self._pubkey is None:
            raise ValueError("certificate builder has no public key")
        return self._pubkey

    @pubkey.setter
    def pubkey(self, pubkey):
        self._pubkey = pubkey

    @property
    def serial(self):
        """ Return a uint64-encoded zero value. Certs are not numbered. """
        if self._serial is not None:
            return self._serial
        return 0

    @serial.setter
    def serial(self, cert_serial):
        self._serial = cert_serial

    @property
    def cert_type(self):
        """ Encode the certificate type, as specified at instantiation """
        if self._cert_type is None:
            raise ValueError("certificate builder has no certificate type set")
        return self._cert_type

    @cert_type.setter
    def cert_type(self, cert_type):
        if cert_type == SSH_CERT_TYPE_USER or cert_type == SSH_CERT_TYPE_HOST:
            self._cert_type = cert_type
        else:
            raise ValueError("cert type must be SSH_CERT_TYPE_USER or SSH_CERT_TYPE_HOST")

    @property
    def valid_after(self):
        try:
            return calendar.timegm(self._valid_after)
        except AttributeError:
            return calendar.timegm(datetime.utcnow().timetuple())

    @valid_after.setter
    def valid_after(self, timestamp):
        self._valid_after = datetime.utcfromtimestamp(timestamp).timetuple()

    @property
    def valid_before(self):
        try:
            return calendar.timegm(self._valid_before)
        except AttributeError:
            return calendar.timegm(
                (datetime.utcnow()+timedelta(hours=self.hours_valid)).timetuple()
            )

    @valid_before.setter
    def valid_before(self, timestamp):
        self._valid_before = datetime.utcfromtimestamp(timestamp).timetuple()

    @property
    def critical_options(self):
        if self._critical_options is not None:
            return self._critical_options.render()
        else:
            return CriticalOptions().render()

    @critical_options.setter
    def critical_options(self, opts):
        self._critical_options = CriticalOptions.parse(opts)

    @property
    def extensions(self):
        if self._extensions is not None:
            return self._extensions.render()
        else:
            return Extensions().render()

    @extensions.setter
    def extensions(self, exts):
        self._extensions = Extensions.parse(exts)

    @property
    def reserved(self):
        return ""

    @property
    def signature_key(self):
        if self._signature_key is None:
            raise AttributeError("this certificate has not been signed and has no signature key")
        return self._signature_key

    @signature_key.setter
    def signature_key(self, sig_key):
        self._signature_key = sig_key

    @property
    def signature(self):
        if self._signature is None:
            raise AttributeError("this certificate has not been signed")
        return self._signature

    @signature.setter
    def signature(self, sig):
        self._signature = sig

    def build_certificate(self):
        if not self.valid_principals or not self.pubkey or not self.cert_type:
            raise ValueError("certificate builder not initialized completely")
        output = encode_string("ssh-ed25519-cert-v01@openssh.com")
        for field_type, fieldname in self.ed25519_format:
            try:
                value = eval("encode_{}(self.__getattribute__(fieldname))".format(field_type))
                output += value
            except AttributeError as err:
                pass # we may not have signature information yet
            except TypeError as err:
                raise TypeError(
                    "could not build cert output using field {} with value {}: {}".format(
                        fieldname, self.__getattribute__(field[1]), err))
        return output

    def load(self, filename):
        with open(filename) as certfile:
            import base64
            raw = base64.b64decode(certfile.read().split(" ")[1])
            return self.loads(raw)

    def loads(self, raw):
        cert_fmt, raw = decode_string(raw)
        if cert_fmt != "ssh-ed25519-cert-v01@openssh.com":
            raise TypeError(
                "certificate {} is not in ssh-ed25519-cert-v01@openssh.com format".format(
                    cert_fmt))
        for fieldtype, fieldname in self.ed25519_format:
            try:
                value, raw = eval("decode_{}(raw)".format(fieldtype))
                self.__setattr__(fieldname, value)
            except ValueError as err:
                raise ValueError("certificate field {} cannot be decoded: {}".format(fieldname, err))
            except AttributeError as err:
                if fieldname == "reserved":
                    continue
                raise

if __name__ == "__main__":
    import sys
    import pprint
    import base64

    # Generate a cert sui generis
    cert = CertificateBuilder("thomas", "user_thomas", pubkey="nosuchkey", cert_type=SSH_CERT_TYPE_USER)
    pprint.pprint(base64.b64encode(cert.build_certificate()))

    # Round-trip a cert from disk
    cert = CertificateBuilder()
    cert.load(sys.argv[1])
    built = cert.build_certificate()
    cert = CertificateBuilder()
    cert.loads(built)
    pprint.pprint(base64.b64encode(cert.build_certificate()))
