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
import zlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


# Marker types
MARKER_LOCK = b'LOCK'
MARKER_NOTE = b'NOTE'
MARKER_ENCODER = b'ENCODER'
MARKER_MASQUERADE = b'MASQUERADE'

MARKER_SIZE = 32


RSA_KEY_SIZE = 256
AES_KEY_SIZE = 16

SENTINEL_SIZE = 16


# PCG32
PCG32_MULT = 0x5851F42D4C957F2D
PCG32_INCR = 0xA17654E46FBE17F3
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

# PCG128
PCG128_MULT = 0x2360ED051FC65DA44385DF649FCCF645
MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def aes_decrypt(enc_data: bytes, key: bytes, pos: int = 0) -> bytes:
    """AES decrypt data"""
    counter = Counter.new(128, initial_value=(pos >> 4), little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ofs = pos & 0xF
    if ofs != 0:
        # Decrypt dummy data
        cipher.decrypt(b'\0' * ofs)
    return cipher.decrypt(enc_data)


def aes_encrypt(data: bytes, key: bytes, pos: int = 0) -> bytes:
    """AES encrypt data"""
    counter = Counter.new(128, initial_value=(pos >> 4), little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ofs = pos & 0xF
    if ofs != 0:
        # Encrypt dummy data
        cipher.encrypt(b'\0' * ofs)
    return cipher.encrypt(data)


def decrypt_and_decompress(enc_data):
    """Decrypt and decompress data"""
    key = enc_data[-AES_KEY_SIZE:]
    pack_data = aes_decrypt(enc_data[:-AES_KEY_SIZE], key)
    return zlib.decompress(pack_data, -15)


def rsa_encrypt(data: bytes, pub_key_data: bytes) -> bytes:
    """RSA encrypt data"""
    key = RSA.import_key(pub_key_data)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(data)


def rsa_decrypt(enc_data: bytes, priv_key_data: bytes) -> bytes:
    """RSA decrypt data"""
    key = RSA.import_key(priv_key_data)
    sentinel = os.urandom(SENTINEL_SIZE)
    cipher = PKCS1_v1_5.new(key)
    data = cipher.decrypt(enc_data, sentinel)
    if data == sentinel:
        return None
    return data


def get_rsa_pubkey_data(priv_key_data: bytes) -> bytes:
    """Get RSA public key data (DER)"""
    key = RSA.import_key(priv_key_data)
    pub_key = key.public_key()
    return pub_key.export_key(format='DER', pkcs=8)


def pcg32_rand(state64: int) -> (int, int):
    """PCG32 pseudo random number generator"""
    state64 = (state64 * PCG32_MULT + PCG32_INCR) & MASK64
    x = ((state64 >> 45) ^ (state64 >> 27)) & MASK32
    shift = state64 >> 59
    rnd32 = (x >> shift) | ((x << (32 - shift)) & MASK32)
    return rnd32, state64


def pcg128_seed(state128, incr128: int) -> (int, int):
    """PCG128 pseudo random number generator"""
    incr128 |= 1
    state128 = (state128 + incr128) & MASK128
    state128 = (state128 * PCG128_MULT) & MASK128
    state128 = (state128 + incr128) & MASK128
    return state128, incr128


def pcg128_from_data(data: bytes) -> bytes:
    """Initialise PCG128 pseudo random number generator state from data"""

    state64 = 1
    for b in data:
        state64 = (state64 + (b if b != 0 else 1)) & MASK64
        if state64 == 0:
            state64 = 1

    state256 = b''
    for _ in range(8):
        rnd32, state64 = pcg32_rand(state64)
        state256 += rnd32.to_bytes(4, byteorder='little')

    state128 = int.from_bytes(state256[:16], byteorder='little')
    incr128 = int.from_bytes(state256[16:32], byteorder='little')
    return pcg128_seed(state128, incr128)


def make_marker(marker_type: bytes, rsa_pub_key_data: bytes) -> bytes:
    """Make marker"""

    state128, incr128 = pcg128_from_data(marker_type + rsa_pub_key_data)

    marker = MARKER_SIZE * [0]

    for i in range(MARKER_SIZE):

        state128 = (state128 * PCG128_MULT) & MASK128
        state128 = (state128 + incr128) & MASK128

        x = state128 >> 64
        shift = x >> 58
        x ^= state128 & MASK64
        marker[i] = ((x >> shift) & 0xFF) | ((x << (64 - shift)) & 0xFF)

    return bytes(marker)


def make_lock_marker(rsa_pub_key_data: bytes) -> bytes:
    """Make marker (LOCK)"""
    return make_marker(MARKER_LOCK, rsa_pub_key_data)


def make_note_marker(rsa_pub_key_data: bytes) -> bytes:
    """Make marker (NOTE)"""
    return make_marker(MARKER_NOTE, rsa_pub_key_data)


def make_encoder_marker(rsa_pub_key_data: bytes) -> bytes:
    """Make marker (ENCODER)"""
    return make_marker(MARKER_ENCODER, rsa_pub_key_data)


def make_masquerade_marker(rsa_pub_key_data: bytes) -> bytes:
    """Make marker (MASQUERADE)"""
    return make_marker(MARKER_MASQUERADE, rsa_pub_key_data)


if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 2:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename')
        exit(0)

    file_name = sys.argv[1]

    with io.open(file_name, 'rb') as f:
        enc_data = f.read()

    data = decrypt_and_decompress(enc_data)

    new_file_name = file_name + '.dec'
    with io.open(new_file_name, 'wb') as f:
        f.write(data)

    print('Done!')
