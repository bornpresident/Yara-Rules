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

import sys
import io
import struct
import os.path
import shutil
import aplib
import lb3_crypt


MAX_METADATA_SIZE = 0x2E0

KEYDATA_SIZE = 0x80
KEYDATA_HASH_SIZE = 4
METADATA_FIXED_SIZE = KEYDATA_SIZE + KEYDATA_HASH_SIZE + 2
MIN_METADATA_SIZE = 0xD8


MAX_BLOCK_SIZE = 0xFA1
DIVIDER = 0x1000F


ENCRYPT_BLOCK_SIZE = 0x20000


def get_data_hash(data, rsa_n_dword0, n=0):
    """Get data hash"""

    n0 = n & 0xFFFF
    n1 = n >> 16

    size = len(data)

    pos = 0

    while (size != 0):

        block_size = min(size, MAX_BLOCK_SIZE)

        for i in range(block_size):
            n0 += data[pos + i]
            n1 += n0

        n0 %= DIVIDER
        n1 %= DIVIDER

        pos += block_size
        size -= block_size

    return ((n0 + (n1 << 16)) & 0xFFFFFFFF) ^ rsa_n_dword0


def get_meta_data_hash(data, rsa_n_dword0):
    """Get metadata hash"""

    h = 0x0D6917A

    for _ in range(3):

        h2 = get_data_hash(data, rsa_n_dword0, h)
        h = int.from_bytes(h2.to_bytes(4, 'little'), 'big')

    return h


def is_file_encrypted(filename, rsa_n_dword0):
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        try:
            f.seek(-(KEYDATA_SIZE + KEYDATA_HASH_SIZE), 2)
        except OSError:
            return False

        keydata = f.read(KEYDATA_SIZE + KEYDATA_HASH_SIZE)

    key_hash = int.from_bytes(keydata[:4], 'little')
    h = get_meta_data_hash(keydata[4:], rsa_n_dword0)
    return (h == key_hash)
        

def read_metadata(filename):
    """Read encrypted file metadata"""

    with io.open(filename, 'rb') as f:
        f.seek(-METADATA_FIXED_SIZE, 2)
        metadata_size = int.from_bytes(f.read(2), 'little')
        metadata_size += METADATA_FIXED_SIZE
        f.seek(-metadata_size, 2)
        metadata = f.read(metadata_size)

    return metadata


def decrypt_metadata(rsa_priv_key_data, metadata):
    """Decrypt metadata"""

    # Decrypt key data
    key_data = lb3_crypt.rsa_decrypt(rsa_priv_key_data,
                                     metadata[-KEYDATA_SIZE:])

    # Check decrypted key data
    rsa_n_dword0, = struct.unpack_from('<L', rsa_priv_key_data,
                                       lb3_crypt.RSA_KEY_SIZE)
    i, = struct.unpack_from('<L', key_data, KEYDATA_SIZE - 4)
    i = (((i * 0x8088405 + 1) & 0xFFFFFFFF) * 0x78) >> 32
    check_num, = struct.unpack_from('<L', key_data, i)
    if rsa_n_dword0 != check_num:
        return None

    # Decrypt metadata
    salsa_key_data = key_data[:lb3_crypt.SALSA_KEY_DATA_SIZE]
    enc_data = metadata[:len(metadata) - METADATA_FIXED_SIZE]
    dec_data = lb3_crypt.salsa_decrypt(salsa_key_data, enc_data)

    return dec_data + \
           metadata[-METADATA_FIXED_SIZE : -METADATA_FIXED_SIZE + 6] + \
           key_data


def decrypt_file(filename, metadata):
    """Decrypt file"""

    pos = len(metadata) - MIN_METADATA_SIZE + 2

    # Block space, first area block last index, next area block last index
    chunk_space, first_chunk_last_block, next_chunk_last_block = \
        struct.unpack_from('<QLL', metadata, pos)
    first_chunk_size = (first_chunk_last_block + 1) * ENCRYPT_BLOCK_SIZE
    next_chunk_size = (next_chunk_last_block + 1) * ENCRYPT_BLOCK_SIZE
    pos += 16

    # Set Salsa decryption key
    key_data = metadata[pos : pos + lb3_crypt.SALSA_KEY_DATA_SIZE]
    cipher = lb3_crypt.Salsa(key_data)

    with io.open(filename, 'rb+') as f:

        # Decrypt first area
        enc_data = f.read(first_chunk_size)
        data = cipher.decrypt(enc_data)
        f.seek(0)
        f.write(data)

        if chunk_space != 0:

            pos = first_chunk_last_block * ENCRYPT_BLOCK_SIZE + chunk_space
            chunk_step = (next_chunk_last_block * ENCRYPT_BLOCK_SIZE +
                          chunk_space)

            while True:

                # Decrypt next area
                f.seek(pos)
                enc_data = f.read(next_chunk_size)
                if enc_data == b'':
                    break

                data = cipher.decrypt(enc_data)
                f.seek(pos)
                f.write(data)

                pos += chunk_step

        # Remove metadata
        f.seek(-len(metadata), 2)
        f.truncate()


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read private RSA key data (d, n)
with io.open('./rsa_privkey.bin', 'rb') as f:
    rsa_priv_key_data = f.read(2 * lb3_crypt.RSA_KEY_SIZE)

# Check if file is encrypted
rsa_n_dword0, = struct.unpack_from('<L', rsa_priv_key_data,
                                   lb3_crypt.RSA_KEY_SIZE)
if not is_file_encrypted(filename, rsa_n_dword0):
    print('Error: file not encrypted or damaged')
    sys.exit(1)

# Read encrypted file metadata
metadata = read_metadata(filename)
print('metadata size: %d' % len(metadata))
metadata_var_size = len(metadata) - METADATA_FIXED_SIZE
print('metadata variable part size: %d' % metadata_var_size)

# Decrypt metadata
metadata = decrypt_metadata(rsa_priv_key_data, metadata)
if metadata is None:
    print('Error: file rsa key not valid')
    sys.exit(1)

new_filename = filename + '.metadata'
with io.open(new_filename, 'wb') as f:
    f.write(metadata)

# Original file name
pos = len(metadata) - MIN_METADATA_SIZE
pack_filename_size, = struct.unpack_from('<H', metadata, pos)
unpacked_filename = aplib.decompress(metadata[:pack_filename_size])
orig_filename = unpacked_filename.decode('UTF-16LE')
i = orig_filename.find('\0')
if i >= 0:
    orig_filename = orig_filename[:i]
print('original file name: \"%s\"' % orig_filename)

# Copy file
dest_filepath = os.path.join(os.path.dirname(os.path.abspath(filename)),
                             orig_filename)
shutil.copy2(filename, dest_filepath)

# Decrypt file
decrypt_file(dest_filepath, metadata)
