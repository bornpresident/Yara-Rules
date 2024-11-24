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
import struct
import shutil
import alphv3_sphx_crypt
import alphv3_sphx_hash


RANSOM_EXT = '.xxxxxxx'


METADATA_BLOCK_SIZE = 512


def is_file_encrypted(filename: str, rsa_pub_key_data: bytes) -> bool:
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:

        # Read marker
        try:
            f.seek(-alphv3_sphx_crypt.MARKER_SIZE, 2)
        except OSError:
            return False

        marker = f.read(alphv3_sphx_crypt.MARKER_SIZE)

    # Check marker
    encoder_marker = alphv3_sphx_crypt.make_encoder_marker(rsa_pub_key_data)
    return (marker == encoder_marker)


def is_ransom_note(filename: str, rsa_pub_key_data: bytes) -> bool:
    """Check if file is a ransom note"""

    with io.open(filename, 'rb') as f:

        # Read marker
        try:
            f.seek(-alphv3_sphx_crypt.MARKER_SIZE, 2)
        except OSError:
            return False

        marker = f.read(alphv3_sphx_crypt.MARKER_SIZE)

    # Check marker
    note_marker = alphv3_sphx_crypt.make_note_marker(rsa_pub_key_data)
    return (marker == note_marker)


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read marker
        offset = -alphv3_sphx_crypt.MARKER_SIZE
        try:
            f.seek(offset, 2)
        except OSError:
            return False

        marker = f.read(alphv3_sphx_crypt.MARKER_SIZE)

        # Check marker
        pub_key_data = alphv3_sphx_crypt.get_rsa_pubkey_data(priv_key_data)
        encoder_marker = alphv3_sphx_crypt.make_encoder_marker(pub_key_data)
        if marker != encoder_marker:
            return False

        # Read number of additional blocks
        offset -= 2
        try:
            f.seek(offset, 2)
        except OSError:
            return False

        num_metadata_blocks = int.from_bytes(f.read(2), byteorder='little')
        max_metadata_size = num_metadata_blocks * METADATA_BLOCK_SIZE

        # Read encrypted AES key
        offset -= alphv3_sphx_crypt.RSA_KEY_SIZE + max_metadata_size
        try:
            f.seek(offset, 2)
        except OSError:
            return False

        enc_key_data = f.read(alphv3_sphx_crypt.RSA_KEY_SIZE)

        # Decrypt AES key
        aes_key = alphv3_sphx_crypt.rsa_decrypt(enc_key_data, priv_key_data)
        if aes_key is None:
            return False

        pos = f.tell()

        # Read metadata
        metadata_size = int.from_bytes(f.read(2), byteorder='big')
        if metadata_size + 2 > max_metadata_size:
            return False

        enc_metadata = f.read(metadata_size)

        # Decrypt metadata
        metadata = alphv3_sphx_crypt.aes_decrypt(enc_metadata, aes_key, pos)

        # Parse metadata (struct FooterContent)
        if len(metadata) < 6:
            return False

        pos = 6

        # Check metadata CRC
        crc, = struct.unpack_from('<H', metadata, 4)
        crc2 = alphv3_sphx_hash.crc16(metadata[pos:])
        crc2 = alphv3_sphx_hash.crc16_finish(crc2)
        if crc != crc2:
            return False

        # struct Mapper
        pos += 12
        block_size, stop_pos, first_chunk_size, chunk_size, chunk_space, \
            file_size, file_size2 = struct.unpack_from('<L6Q', metadata, pos)

        pos += 0x34
        pos += 0xC if (metadata[pos] == 0) else 0x10

        # Original file path
        orig_filepath = ''
        if (metadata[pos] != 0):
            pos += 1
            orig_filepath_len, = struct.unpack_from('<Q', metadata, pos)
            pos += 8
            orig_filepath = metadata[pos : pos + orig_filepath_len].decode()

        print(orig_filepath)

        # Decrypt file data
        pos = 0

        if first_chunk_size != 0:

            # Decrypt first chunk
            size = min(first_chunk_size, stop_pos - pos)
            p = pos

            while size != 0:

                s = min(size, block_size)
                f.seek(p)
                enc_data = f.read(s)
                if enc_data == b'':
                    break

                data = alphv3_sphx_crypt.aes_decrypt(enc_data, aes_key, p)

                f.seek(p)
                f.write(data)

                size -= s
                p += s

            pos += first_chunk_size + chunk_space

        # Decrypt chunks
        while pos < stop_pos:

            size = min(chunk_size, stop_pos - pos)
            p = pos

            while size != 0:

                s = min(size, block_size)
                f.seek(p)
                enc_data = f.read(s)
                if enc_data == b'':
                    break

                data = alphv3_sphx_crypt.aes_decrypt(enc_data, aes_key, p)

                f.seek(p)
                f.write(data)

                size -= s
                p += s

            pos += chunk_size + chunk_space

        # Remove metadata
        f.truncate(file_size)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./example_privkey.bin', 'rb') as f:
    priv_key_data = f.read()

pub_key_data = alphv3_sphx_crypt.get_rsa_pubkey_data(priv_key_data)

# Check if file is a ransom note
if is_ransom_note(filename, pub_key_data):
    print(os.path.basename(filename), '- ransom note')
    sys.exit(0)

# Check if file is encrypted
if not is_file_encrypted(filename, pub_key_data):
    print(os.path.basename(filename), '- not encrypted or damaged')
    sys.exit(0)

print(os.path.basename(filename), '- encrypted')

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
