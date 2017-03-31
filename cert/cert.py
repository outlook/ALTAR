"""

Build OpenSSH certificates erryday.

References:
    https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.certkeys

"""

#pylint: disable=missing-docstring

import base64
import calendar
from datetime import datetime, timedelta
from random import getrandbits
from struct import error as struct_error

from .formats import ssh_certificate_formats, ssh_signature_formats
from .encodec import encode_string, decode_string
from .sign import certificate_signing_methods


class CriticalOptions(object): #pylint: disable=too-few-public-methods
    ordered_opts = ['force-command', 'source-addresses']

    def __init__(self, force_command=None, source_addresses=None):
        self.force_command = force_command
        self.source_addresses = source_addresses

    def dump(self):
        obj = {}
        if self.force_command is not None:
            obj['force-command'] = self.force_command
        if self.source_addresses is not None:
            obj['source-addresses'] = self.source_addresses

        return obj

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

class Extensions(object):                                                           #pylint: disable=too-few-public-methods
    ordered_exts = ['permit-X11-forwarding', 'permit-agent-forwarding',
                    'permit-port-forwarding', 'permit-pty', 'permit-user-rc']

    def __init__(self, permit_X11_forwarding=False, permit_agent_forwarding=False,  #pylint: disable=too-many-arguments
                 permit_port_forwarding=False, permit_pty=False, permit_user_rc=False):
        self.permit_X11_forwarding = permit_X11_forwarding                          #pylint: disable=invalid-name
        self.permit_agent_forwarding = permit_agent_forwarding
        self.permit_port_forwarding = permit_port_forwarding
        self.permit_pty = permit_pty
        self.permit_user_rc = permit_user_rc

    def dump(self):
        return [v for v in self.__dict__.keys() if self.__getattribute__(v)]

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


class SSHCertificate(object):                                                       #pylint: disable=too-many-instance-attributes
    SSH_CERT_TYPE_USER = 1
    SSH_CERT_TYPE_HOST = 2

    def __init__(self, certificate_format):
        if certificate_format not in ssh_certificate_formats:
            raise ValueError("certificate format {} not supported".format(certificate_format))
        self.certificate_format = certificate_format
        self.nonce = str(bytearray(getrandbits(8) for _ in range(32)))
        self.serial = 0
        self.hours_valid = 3
        self._now = datetime.utcnow()

    @property
    def valid_after(self):
        try:
            return calendar.timegm(self._valid_after)
        except AttributeError:
            return calendar.timegm(self._now.timetuple())

    @valid_after.setter
    def valid_after(self, timestamp):
        self._valid_after = datetime.utcfromtimestamp(timestamp).timetuple()        #pylint: disable=attribute-defined-outside-init

    @property
    def valid_before(self):
        try:
            return calendar.timegm(self._valid_before)
        except AttributeError:
            return calendar.timegm(
                (self._now+timedelta(hours=self.hours_valid)).timetuple()
            )

    @valid_before.setter
    def valid_before(self, timestamp):
        self._valid_before = datetime.utcfromtimestamp(timestamp).timetuple()       #pylint: disable=attribute-defined-outside-init

    @property
    def critical_options(self):
        if self._critical_options is not None:
            return self._critical_options.render()
        else:
            return CriticalOptions().render()

    @critical_options.setter
    def critical_options(self, opts):
        if isinstance(opts, CriticalOptions):
            self._critical_options = opts                                           #pylint: disable=attribute-defined-outside-init
        else:
            self._critical_options = CriticalOptions.parse(opts)                    #pylint: disable=attribute-defined-outside-init

    @property
    def extensions(self):
        if self._extensions is not None:
            return self._extensions.render()
        else:
            return Extensions().render()

    @extensions.setter
    def extensions(self, exts):
        if isinstance(exts, Extensions):
            self._extensions = exts                                                 #pylint: disable=attribute-defined-outside-init
        else:
            self._extensions = Extensions.parse(exts)                               #pylint: disable=attribute-defined-outside-init

    @property
    def reserved(self):
        return ""

    def build_certificate(self):
        output = encode_string(self.certificate_format)

        for field_type, fieldname in ssh_certificate_formats[self.certificate_format]:
            try:
                value = field_type.encode(self.__getattribute__(fieldname))
                output += value
            except AttributeError as err:
                # Which fields are required depends on the relevant format (see formats.py).
                # A missing "signature" field is acceptable because the certificate may not yet
                # be signed and we hash the cert minus this field for signing.
                if not fieldname == "signature":
                    raise AttributeError(
                        "building cert of type {} failed! {} field missing".format(
                            self.certificate_format, fieldname
                        )
                    )
            except TypeError as err:
                raise TypeError(
                    "could not build cert output using field {} with value {}: {}".format(
                        fieldname, self.__getattribute__(fieldname), err))
        return output

    @classmethod
    def load(cls, filename):
        with open(filename) as certfile:
            raw = base64.b64decode(certfile.read().split(" ")[1])
            return cls.loads(raw)

    @classmethod
    def loads(cls, raw):
        cert_fmt, raw = decode_string(raw)
        if cert_fmt not in ssh_certificate_formats:
            raise NotImplementedError(
                "certificate type {} is not one of the implemented formats".format(
                    cert_fmt))
        newcert = cls(cert_fmt)
        for fieldtype, fieldname in ssh_certificate_formats[cert_fmt]:
            try:
                value, raw = fieldtype.decode(raw)
                newcert.__setattr__(fieldname, value)
            except ValueError as err:
                raise ValueError(
                    "certificate field {} cannot be decoded: {}".format(fieldname, err)
                )
            except AttributeError as err:
                if fieldname == "reserved":
                    continue
                raise
            except struct_error as err:
                raise ValueError("certificate field {} could not be decoded from {}: {}".format(
                    fieldname, repr(raw), err
                ))
            #print "set field {} to value {}".format(fieldname, repr(value))
        return newcert

    def sign(self, private_key):
        # get key type field (e.g. "ssh-rsa") from the signature_key
        key_type = decode_string(self.signature_key)[0]                             #pylint: disable=no-member
        if key_type not in certificate_signing_methods:
            raise NotImplementedError("cannot sign certificate with a {} key".format(key_type))
        raw_signature = certificate_signing_methods[key_type](
            self.build_certificate(),
            private_key
        )
        try:
            self.__delattr__("signature")
        except AttributeError:
            pass
        self.signature = encode_string(key_type)                                    #pylint: disable=attribute-defined-outside-init
        for fieldtype, fieldname in ssh_signature_formats[key_type]:
            self.signature += fieldtype.encode(raw_signature[fieldname])
