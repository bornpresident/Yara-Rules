# MIT License
#
# Copyright (c) 2023-2024 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import os
import math
import struct
from secrets import randbelow


DIGITS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
RND_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def encode_data(data: bytes) -> str:
    """Encode data to string"""

    x = int.from_bytes(data, byteorder='big')

    s = ''
    while x != 0:
        x, n = divmod(x, len(DIGITS))
        s = DIGITS[n] + s

    num_null_bytes = 0
    for b in data:
        if b != 0:
            break
        num_null_bytes += 1

    if num_null_bytes != 0:
        num_null_digits = int((num_null_bytes * 8) / math.log2(len(DIGITS)))
        s = num_null_digits * DIGITS[0] + s

    return s


def decode_data(s: str) -> bytes:
    """Decode data from string"""

    x = 0

    num_null_digits = 0

    for c in s:
        n = DIGITS.find(c)
        if n < 0:
            raise ValueError('Invalid character')
        elif (n == 0) and (x == 0):
            num_null_digits += 1
        x = x * len(DIGITS) + n

    num_bytes = (x.bit_length() + 7) // 8

    if num_null_digits != 0:
        num_bytes += int(num_null_digits / math.log(256, len(DIGITS))) + 1

    return x.to_bytes(num_bytes, byteorder='big')


def get_rnd_str(length: int) -> str:
    """Generate random string"""
    s = ''
    for _ in range(length):
        s += RND_CHARS[randbelow(len(RND_CHARS))]
    return s


def get_data_blob(data: bytes) -> bytes:
    """Get data BLOB"""
    data_size = len(data)
    return data_size.to_bytes(8, byteorder='little') + bytes(data)


def extract_data_from_blob(data: bytes, pos: int = 0) -> bytes:
    """Extract data from BLOB"""
    if (pos >= len(data)) or (len(data) - pos < 8):
        return None
    data_size, = struct.unpack_from('<Q', data, pos)
    if data_size > len(data) - (pos + 8):
        return None
    return data[pos + 8 : pos + 8 + data_size]


if __name__ == '__main__':
    import sys
    import io
    import os

    if ((len(sys.argv) != 3) or
        ((sys.argv[1] != '-e') and (sys.argv[1] != '-d'))):
        print('Usage:', os.path.basename(sys.argv[0]), '-e|-d filename')
        sys.exit(0)

    filename = sys.argv[2]

    if sys.argv[1] == '-e':

        with io.open(filename, 'rb') as f:
            data = f.read()

        enc_str = encode_data(data)

        new_filename = filename + '.enc'
        with io.open(new_filename, 'wt') as f:
            f.write(enc_str)

    else:

        with io.open(filename, 'rt') as f:
            s = f.read()

        dec_data = decode_data(s)

        new_filename = filename + '.dec'
        with io.open(new_filename, 'wb') as f:
            f.write(dec_data)
