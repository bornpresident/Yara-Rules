# MIT License
#
# Copyright (c) 2023 Andrey Zhdanov (rivitna)
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

import sys
import io
import os
import shutil
import binascii
import struct


# Encrypted PE sections
ENC_SECTIONS = [
    b'.text\0\0\0',
    b'.data\0\0\0',
    b'.pdata\0\0',
]


PASSWORD_LEN = 16
DERIVE_KEY_ITERATIONS = 6


MASK32 = 0xFFFFFFFF

rol32 = lambda v, s: ((v << s) & MASK32) | ((v & MASK32) >> (32 - s))

ror32 = lambda v, s: ((v & MASK32) >> s) | ((v << (32 - s)) & MASK32)

bswap32 = lambda v: \
    ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | \
    ((v & 0xFF0000) >> 8) | ((v >> 24) & 0xFF)


def derive_key(pwd):
    """Derive key from password"""
    key_data = b''

    x = list(struct.unpack('<4L', pwd))

    for _ in range(DERIVE_KEY_ITERATIONS):
        x[0] = (ror32(bswap32(x[0]), 13) ^ MASK32) ^ bswap32(rol32(x[1], 11))
        x[1] = bswap32(rol32(x[2], 9))
        x[2] = (x[1] ^ MASK32) ^ bswap32(rol32(x[3], 7))
        x[3] = (x[2] ^ MASK32) ^ rol32(x[2], 5)
        key_data += struct.pack('<4L', *x)

    return key_data


def vmpc_ksa3(key_data):
    """VMPC KSA3"""
    p = list(range(256))

    key = key_data[32:]
    iv = key_data[:32]

    s = 0

    for _ in range(3):
        for i in range(256):
            s = p[(s + p[i] + key[i % len(key)]) & 0xFF]
            p[i], p[s] = p[s], p[i]

    for _ in range(3):
        for i in range(256):
            s = p[(s + p[i] + iv[i % len(iv)]) & 0xFF]
            p[i], p[s] = p[s], p[i]

    for _ in range(3):
        for i in range(256):
            s = p[(s + p[i] + key[i % len(key)]) & 0xFF]
            p[i], p[s] = p[s], p[i]

    return p, s


def vmpc_prga(p, s):
    """VMPC PRGA"""
    i = 0
    while True:
        s = p[(s + p[i]) & 0xFF]
        x = p[(p[p[s]] + 1) & 0xFF]
        p[i], p[s] = p[s], p[i]
        i = (i + 1) & 0xFF
        yield x


def decrypt_pe_file(filename, pwd):
    """Decrypt PE file"""

    with io.open(filename, 'rb+') as f:

        # Read DOS header
        dos_hdr = f.read(0x40)

        mz_sign, = struct.unpack_from('<H', dos_hdr, 0)
        if (mz_sign != 0x5A4D):
            return 0

        # Read NT header part
        nt_hdr_pos, = struct.unpack_from('<L', dos_hdr, 0x3C)
        f.seek(nt_hdr_pos)
        nt_hdr = f.read(0x16)

        pe_sign, = struct.unpack_from('<L', nt_hdr, 0)
        if (pe_sign != 0x00004550):
            return 0

        # Parse PE header
        num_sections, = struct.unpack_from('<H', nt_hdr, 6)
        opt_hdr_size, = struct.unpack_from('<H', nt_hdr, 0x14)
        nt_hdr_size = 4 + 0x14 + opt_hdr_size
        first_section_hdr_pos = nt_hdr_pos + nt_hdr_size

        f.seek(first_section_hdr_pos)
        sec_hdr_data = f.read(num_sections * 0x28)

        key_data = derive_key(pwd)
        p, s = vmpc_ksa3(key_data)

        num_dec_sections = 0

        # Enumerate PE sections
        pos = 0

        for i in range(num_sections):

            s_name = sec_hdr_data[pos : pos + 8]
            if s_name in ENC_SECTIONS:

                # Decrypt section data
                s_psize, s_pos = struct.unpack_from('<2L', sec_hdr_data, pos + 16)

                f.seek(s_pos)
                sec_data = bytearray(f.read(s_psize))

                keystream = vmpc_prga(p, s)

                for i in range(s_psize):
                    sec_data[i] ^= next(keystream)

                f.seek(s_pos)
                f.write(sec_data)

                num_dec_sections += 1

            pos += 0x28

    return num_dec_sections


#
# Main
#
if len(sys.argv) != 3:
    print('Usage:', os.path.basename(sys.argv[0]), 'pass filename')
    sys.exit(0)

pwd = binascii.unhexlify(sys.argv[1])
if len(pwd) != PASSWORD_LEN:
    print('Error: Invalid password.')
    sys.exit(1)

filename = sys.argv[2]
with io.open(filename, 'rb') as f:
    file_data = bytearray(f.read())

new_filename = filename + '.dec'
shutil.copy2(filename, new_filename)

# Decrypt PE file
num_dec_sections = decrypt_pe_file(new_filename, pwd)
if num_dec_sections == 0:
    print('Error: File not encrypted or damaged.')
    sys.exit(1)

print('Decrypted sections: %d' % num_dec_sections)
