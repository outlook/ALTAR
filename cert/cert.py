"""

Build OpenSSH certificates erryday.

"""

#pylint: disable=missing-docstring

import base64
import calendar
from datetime import datetime, timedelta
from random import getrandbits
from struct import error as struct_error

from .formats import ssh_certificate_formats
from .encodec import encode_string, decode_string

SSH_CERT_TYPE_USER = 1
SSH_CERT_TYPE_HOST = 2

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

    def __init__(self, user_id=None, key_id=None, pubkey=None, cert_type=None, hours_valid=3,  #pylint: disable=too-many-arguments
                 crit_opts=None, exts=None):
        self.key_id = key_id
        self.valid_principals = [user_id] if user_id else None
        self._cert_type = cert_type
        self._critical_options = crit_opts
        self._extensions = exts
        self.nonce = str(bytearray(getrandbits(8) for _ in range(32)))
        self.serial = 0
        self.pubkey = pubkey

        self.hours_valid = hours_valid

    @property
    def cert_type(self):
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
        self._valid_after = datetime.utcfromtimestamp(timestamp).timetuple()        #pylint: disable=attribute-defined-outside-init

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
        self._valid_before = datetime.utcfromtimestamp(timestamp).timetuple()       #pylint: disable=attribute-defined-outside-init

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

    def build_certificate(self, certificate_format):
        if certificate_format not in ssh_certificate_formats:
            raise NotImplementedError("no definition available for requested format {}".format(
                certificate_format
            ))

        output = encode_string(certificate_format)

        for field_type, fieldname in ssh_certificate_formats[certificate_format]:
            try:
                value = field_type.encode(self.__getattribute__(fieldname))
                output += value
                #print "appended field {} with value {}".format(fieldname, repr(value))
            except AttributeError as err:
                if not fieldname == "signature" and not fieldname == "signature_key":
                    raise AttributeError(
                        "building cert of type {} failed! {} field missing".format(
                            certificate_format, fieldname)
                    )
            except TypeError as err:
                raise TypeError(
                    "could not build cert output using field {} with value {}: {}".format(
                        fieldname, self.__getattribute__(fieldname), err))
        return output

    def load(self, filename):
        with open(filename) as certfile:
            raw = base64.b64decode(certfile.read().split(" ")[1])
            return self.loads(raw)

    def loads(self, raw):
        cert_fmt, raw = decode_string(raw)
        if cert_fmt not in ssh_certificate_formats:
            raise NotImplementedError(
                "certificate type {} is not one of the implemented formats".format(
                    cert_fmt))
        for fieldtype, fieldname in ssh_certificate_formats[cert_fmt]:
            try:
                value, raw = fieldtype.decode(raw)
                self.__setattr__(fieldname, value)
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
