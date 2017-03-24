"""

Encode/Decoder types for the various data types specified in
RFC 4251 section 5, "Data Type Representations Used in the SSH Protocols"

https://www.ietf.org/rfc/rfc4251.txt

Not implemented:
  * boolean
  * name-list

The 'packedlist' type is described in "The Secure Shell (SSH) Protocol Architecture",
but is not specified in the RFC. It is implemented here for convenience.

"""

#pylint: disable=missing-docstring,invalid-name

from collections import namedtuple
import math
from struct import pack, unpack, error as struct_error


def _num_bytes(value):
    return int(math.ceil(value.bit_length() / 8.0))


# uint32

def encode_uint32(value):
    if value > 2**32 -1:
        raise ValueError("cannot pack {} into uint32".format(value))
    return pack("!I", value)

def decode_uint32(value):
    return unpack('!I', value[:4])[0], value[4:]

# uint64

def encode_uint64(value):
    if value > 2**64 - 1:
        raise ValueError("cannot pack {} into uint64".format(value))
    return pack("!Q", value)

def decode_uint64(value):
    return unpack('>Q', value[:8])[0], value[8:]

# string

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

# packedlist (a string-style list of adjacent strings)

def encode_packedlist(value):
    return encode_string(''.join([encode_string(v) for v in value]))

def decode_packedlist(value):
    joined, remaining = decode_string(value)
    encoded_list = []
    while len(joined) > 0:
        try:
            elem, joined = decode_string(joined)
        except struct_error as err:
            raise ValueError(
                "could not decode packedlist element value {}: {}".format(repr(joined), err)
            )
        encoded_list.append(elem)
    return encoded_list, remaining

# mpint (multiple-precision integer aka signed int of arbitrary size)

def encode_mpint(value):
    if value == 0:
        return '\x00'*4

    blen = _num_bytes(value)
    high_bit = value.bit_length() % 8 == 0
    blen += 1 if high_bit else 0

    twos_comp = bin(value % (1<<(blen*8)))[2:]   # gives -0x20 -> '11100000'
    twos_comp = twos_comp.rjust(blen*8, '0')     # add leading zeros for high-bit positives

    output = bytearray()
    while twos_comp:
        byte, twos_comp = twos_comp[:8], twos_comp[8:]
        output.append(chr(int(byte, 2)))

    return pack("!I{}s".format(blen), blen, str(output))

def decode_mpint(value):
    if value[:4] == '\x00\x00\x00\x00':
        return 0, value[4:]

    def _shift_sum(int_arr):
        return sum([c << i*8 for i, c in enumerate(int_arr[::-1])])

    size = unpack('>I', value[:4])[0]+4
    result = map(ord, value[4:size]) # from string of bytes to array of ints

    if result[0] & (1<<7): # is high bit set? (i.e. is value negative?)
        # find two's complement: invert bits and add one to the sum
        result = _shift_sum([c ^ 0xFF for c in result]) + 1
        return result * -1, value[size:]

    return _shift_sum(result), value[size:]


SSHDataType = namedtuple("SSH_data_type", "encode decode")

uint32 = SSHDataType(encode_uint32, decode_uint32)
uint64 = SSHDataType(encode_uint64, decode_uint64)
string = SSHDataType(encode_string, decode_string)
packedlist = SSHDataType(encode_packedlist, decode_packedlist)
mpint = SSHDataType(encode_mpint, decode_mpint)

__all__ = [
    "mpint",
    "packedlist",
    "string",
    "uint32",
    "uint64",
]
