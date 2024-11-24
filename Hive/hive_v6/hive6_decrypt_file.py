"""
Hive v6 file decrypting.

GitHub: https://github.com/rivitna/
Twitter: @rivitna2
"""

import sys
import os
import io
import shutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Crypto.Cipher import ChaCha20


# Encryption marker / Attacker ID (?) (hardcoded in the sample)
ENC_MARKER = b'\x6B\x5B\x59\xD5\x07\x83\x6E\x28\xA2\x51\xF3\x3B\xDA\x52'
# Encryption marker file position (hardcoded in the sample)
ENC_MARKER_POS = 0x3E
ENC_MARKER_SIZE = len(ENC_MARKER) + 4


METADATA_SIZE = 0x280

NUM_KEYS = 9
BLOCK_SIZE = 0x200
BUFFER_SIZE = 0x4000


def is_file_encrypted(filename):
    """Check if file is encrypted"""

    with io.open(filename, 'rb') as f:
        f.seek(ENC_MARKER_POS)
        marker = f.read(ENC_MARKER_SIZE)

    if len(marker) != ENC_MARKER_SIZE:
        return False

    return marker[4:] == ENC_MARKER


def rsa_decrypt(rsa_priv_key, enc_data):
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(rsa_priv_key, hashAlgo=SHA3_512)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def prepare_decryptors(key_data):
    """Prepare decryptors"""

    decryptors = []

    pos = 0

    for i in range (NUM_KEYS):
        # Derive key using HChaCha20
        key = ChaCha20._HChaCha20(key_data[pos : pos + 32],
                                  key_data[pos + 32 : pos + 48])

        nonce = b'\0' * 4 + key_data[pos + 48 : pos + 56]
        decryptors.append(ChaCha20.new(key=key, nonce=nonce))

        pos += 56

    return decryptors


def decrypt_file(rsa_priv_keys, filename):
    """Decrypt file data"""

    with io.open(filename, 'rb+') as f:

        f.seek(ENC_MARKER_POS)
        marker = f.read(ENC_MARKER_SIZE)

        try:
            f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        except OSError:
            return False

        # Read metadata
        metadata = f.read(METADATA_SIZE + ENC_MARKER_SIZE)
        orig_data = metadata[:ENC_MARKER_SIZE]
        metadata = metadata[ENC_MARKER_SIZE:]

        # Decrypt metadata
        for rsa_priv_key in rsa_priv_keys:
            key_data = rsa_decrypt(rsa_priv_key, metadata)
            if key_data is not None:
                break
        else:
            return False

        # Remove metadata
        f.seek(-(METADATA_SIZE + ENC_MARKER_SIZE), 2)
        f.truncate()

        # Restore original data
        f.seek(ENC_MARKER_POS)
        f.write(orig_data)

        # Prepare decryptors
        decryptors = prepare_decryptors(key_data)

        # Decrypt data
        pos = ENC_MARKER_POS + ENC_MARKER_SIZE
        key_index = 0

        while True:

            f.seek(pos)
            enc_data = f.read(BUFFER_SIZE)

            dec_data = b''

            for block in (enc_data[i : i + BLOCK_SIZE]
                          for i in range(0, len(enc_data), BLOCK_SIZE)):
                dec_data += decryptors[key_index].decrypt(block)
                key_index = (key_index + 1) % NUM_KEYS

            f.seek(pos)
            f.write(dec_data)

            if len(enc_data) < BUFFER_SIZE:
                break

            pos += BUFFER_SIZE

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage: ' + sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]

rsa_priv_keys = []

# Read private RSA key DER data
with io.open('rsa_privkey0.bin', 'rb') as f:
    rsa_priv_keys.append(RSA.import_key(f.read()))
with io.open('rsa_privkey1.bin', 'rb') as f:
    rsa_priv_keys.append(RSA.import_key(f.read()))

# Check if file is encrypted
if not is_file_encrypted(filename):
    print('Error: The file is damaged or not encrypted')
    sys.exit(1)

dest_filename = filename + '.dec'

# Copy file
shutil.copy2(filename, dest_filename)

# Decrypt file
if not decrypt_file(rsa_priv_keys, dest_filename):
    os.remove(dest_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
