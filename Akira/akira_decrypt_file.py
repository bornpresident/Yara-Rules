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
import os
import shutil
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import chacha


RANSOM_EXT = '.akira'


# RSA
RSA_KEY_SIZE = 512

# ChaCha20/8
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 8
CHACHA_ROUNDS = 8

METADATA_SIZE = RSA_KEY_SIZE + 22


ENC_BLOCK_SIZE = 0x10000


SENTINEL_SIZE = 16


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA decrypt data"""
    key = RSA.import_key(priv_key_data)
    sentinel = os.urandom(SENTINEL_SIZE)
    cipher = PKCS1_v1_5.new(key)
    data = cipher.decrypt(enc_data[::-1], sentinel)
    if data == sentinel:
        return None
    return data


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            return False

        metadata = f.read(METADATA_SIZE)

        # Encryption mode (0 - full, 1 - part, 2 - spot)
        enc_mode = metadata[RSA_KEY_SIZE + 12]
        if not (0 <= enc_mode <= 2):
            return False

        # Encryption percent (0..100)
        enc_percent = metadata[RSA_KEY_SIZE + 13]
        if not (0 <= enc_percent <= 100):
            return False

        file_size, = struct.unpack_from('<Q', metadata, RSA_KEY_SIZE + 14)

        if enc_mode == 0:
            # full
            # (.avdx .vhd .pvm .bin .avhd .vsv .vmx .vmsn .vmsd .vmrs .vmem
            #  .vmcx .vhdx .vmdk .nvram .iso .raw .qcow2 .vdi .subvol)
            num_chunks = 1
            chunk_size = file_size
            chunk_step = 0
        elif enc_mode == 1:
            # part (file size <= 2000000)
            num_chunks = 1
            chunk_size = (file_size * enc_percent) // 100
            chunk_step = 0
        else:
            # spot (file size > 2000000)
            enc_size = (file_size * enc_percent) // 100
            n = 3 if (enc_percent < 50) else 5
            chunk_size = enc_size // n
            num_chunks = 2 if (enc_percent < 50) else 4
            chunk_step = (file_size - chunk_size * num_chunks) // n

        # Decrypt ChaCha20 key and nonce
        enc_key_data = metadata[:RSA_KEY_SIZE]
        key_data = rsa_decrypt(enc_key_data, priv_key_data)
        if key_data is None:
            return False

        key = key_data[:CHACHA_KEY_SIZE]
        nonce = key_data[CHACHA_KEY_SIZE :
                         CHACHA_KEY_SIZE + CHACHA_NONCE_SIZE]

        # Remove metadata
        f.truncate(file_size)

        # Decrypt file data
        chacha_blocks_per_chunk = (chunk_size + (64 - 1)) // 64

        pos = 0

        for i in range(num_chunks):

            # Decrypt chunk
            cipher = chacha.ChaCha(key, nonce, i * chacha_blocks_per_chunk,
                                   CHACHA_ROUNDS)

            p = pos
            size = chunk_size
            while size != 0:

                block_size = min(size, ENC_BLOCK_SIZE)
                f.seek(p)
                enc_data = f.read(block_size)
                if enc_data == b'':
                    break

                dec_data = cipher.decrypt(enc_data)

                f.seek(p)
                f.write(dec_data)

                size -= block_size
                p += block_size

            else:
                pos += chunk_step
                continue

            break
        
    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./rsa_privkey.pem', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    print('Error: Failed to decrypt file')
    sys.exit(1)
