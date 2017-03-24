"""

Encode and decode OpenSSH public key files.

"""

#pylint: disable=missing-docstring

import base64
from struct import error as struct_error

from .formats import ssh_pubkey_formats
from .encodec import encode_string, decode_string

class SSHPublicKeyFile(object):
    def __init__(self):
        pass

    def build_keyfile(self, pubkey_fmt):
        if pubkey_fmt not in ssh_pubkey_formats:
            raise NotImplementedError("pubkey format {} is not supported".format(pubkey_fmt))

        output = encode_string(pubkey_fmt)
        for field_type, fieldname in ssh_pubkey_formats[pubkey_fmt]:
            try:
                value = field_type.encode(self.__getattribute__(fieldname))
                output += value
                #print "appended field {} with value {}".format(fieldname, repr(value))
            except TypeError as err:
                raise TypeError(
                    "could not build pubkey output using field {} with value {}: {}".format(
                        fieldname, self.__getattribute__(fieldname), err))
        return output

    @classmethod
    def load(cls, filename):
        with open(filename) as pubkeyfile:
            raw = base64.b64decode(pubkeyfile.read().split(' ')[1])
            return cls.loads(raw)

    @classmethod
    def loads(cls, raw):
        pubkey_fmt, raw = decode_string(raw)
        if pubkey_fmt not in ssh_pubkey_formats:
            raise NotImplementedError("pubkey format {} is not supported".format(pubkey_fmt))

        newkey = cls()
        for fieldtype, fieldname in ssh_pubkey_formats[pubkey_fmt]:
            try:
                value, raw = fieldtype.decode(raw)
                newkey.__setattr__(fieldname, value)
            except ValueError as err:
                raise ValueError(
                    "key file field {} cannot be decoded: {}".format(fieldname, err)
                )
            except AttributeError as err:
                if fieldname == "reserved":
                    continue
                raise
            except struct_error as err:
                raise ValueError("key file field {} could not be decoded from {}: {}".format(
                    fieldname, repr(raw), err
                ))
        return newkey
