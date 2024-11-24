import sys
import io
import os
import struct


# RSA
RSA_KEY_SIZE = 512

METADATA_SIZE = RSA_KEY_SIZE + 22


# Encrypt modes
ENC_MODES = [
    "full",
    "part",
    "spot"
]


def print_encfile_info(filename: str) -> bool:
    """Get encrypted file info"""

    with io.open(filename, 'rb') as f:

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

        print('file size:  %d' % file_size)
        print('mode:       %d (%s)' % (enc_mode, ENC_MODES[enc_mode]))
        print('percent:    %d' % enc_percent)
        print('chunks:     %d' % num_chunks)
        print('chunk size: %08Xh' % chunk_size)

        if enc_mode == 2:
            print('chunk step: %08Xh' % chunk_step)
        
    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Get encrypted file info
if not print_encfile_info(filename):
    print('Error: file not encrypted or damaged')
    sys.exit(1)
