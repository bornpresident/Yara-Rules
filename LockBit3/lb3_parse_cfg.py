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
import errno
import struct
import base64
import binascii
import json
import aplib
import lb3_dec
import lb3_hash
import lb3_id


# Configuration data file position
# If None try detect automatically position
CFG_POS = None  # 0x22E00
# Helper code file position
# If None try detect automatically position
HELPER_CODE_POS = None  # 0x22BBB

# Configuration data section name
CFG_SECTION_NAME = b'.pdata'
# Data section name
DATA_SECTION_NAME = b'.data'

# Encrypted helper code xor mask
HELPER_CODE_XOR_MASK = 0x30


# Ransom note name
RANSOM_NOTE_NAME = 'README.txt'


RSA_KEY_SIZE = 0x80
UID_SIZE = 0x10
AES_KEY_SIZE = 0x10


# Settings
SETTING_UNKNOWN = 0
SETTING_BOOL = 1
SETTING_WORD = 2
SETTING_ENC_MODE = 3

# Encrypt modes
ENC_MODES = {
    0: 'fast',
    1: 'auto'
}

SETTINGS = [
    ( 'encrypt_mode',        SETTING_ENC_MODE ),
    ( 'encrypt_filename',    SETTING_BOOL ),
    ( 'impersonation',       SETTING_BOOL ),
    ( 'skip_hidden_folders', SETTING_BOOL ),
    ( 'language_check',      SETTING_BOOL ),
    ( 'local_disks',         SETTING_BOOL ),
    ( 'network_shares',      SETTING_BOOL ),
    ( 'kill_processes',      SETTING_BOOL ),
    ( 'kill_services',       SETTING_BOOL ),
    ( 'running_one',         SETTING_BOOL ),
    ( 'print_note',          SETTING_BOOL ),
    ( 'set_wallpaper',       SETTING_BOOL ),
    ( 'set_icons',           SETTING_BOOL ),
    ( 'send_report',         SETTING_BOOL ),
    ( 'self_destruct',       SETTING_BOOL ),
    ( 'kill_defender',       SETTING_BOOL ),
    ( 'wipe_freespace',      SETTING_BOOL ),
    ( 'psexec_netspread',    SETTING_BOOL ),
    ( 'gpo_netspread',       SETTING_BOOL ),
    ( 'gpo_ps_update',       SETTING_BOOL ),
    ( 'shutdown_system',     SETTING_BOOL ),
    ( 'delete_eventlogs',    SETTING_BOOL ),
    ( 'delete_gpo_delay',    SETTING_WORD ),
]


# Fields
FIELD_UNKNOWN = 0
FIELD_STRLIST = 1
FIELD_HASHLIST = 2
FIELD_TEXT = 3

FIELDS = [
    ( 'white_folders',   FIELD_HASHLIST, False ),
    ( 'white_files',     FIELD_HASHLIST, False ),
    ( 'white_extens',    FIELD_HASHLIST, False ),
    ( 'white_hosts',     FIELD_HASHLIST, False ),
    ( 'unknown',         FIELD_UNKNOWN,  False ),
    ( 'kill_processes',  FIELD_STRLIST,  False ),
    ( 'kill_services',   FIELD_STRLIST,  False ),
    ( 'gate_urls',       FIELD_STRLIST,  False ),
    ( 'impers_accounts', FIELD_STRLIST,  True ),
    ( 'note',            FIELD_TEXT,     True ),
]


def load_hash_list(file_name):
    """Load hash list"""

    try:
        with io.open(file_name, 'rt', encoding='utf-8') as f:
            str_list = f.read().splitlines()

    except FileNotFoundError:
        return {}

    return { lb3_hash.get_wide_str_hash(s): s for s in str_list if s != '' }


def get_lb3_info(file_data):
    """
    Get sample information:
        - configuration data position;
        - encrypted helper code position.
    """

    mz_sign, = struct.unpack_from('<H', file_data, 0)
    if (mz_sign != 0x5A4D):
        return None

    nt_hdr_pos, = struct.unpack_from('<L', file_data, 0x3C)

    pe_sign, = struct.unpack_from('<L', file_data, nt_hdr_pos)
    if (pe_sign != 0x00004550):
        return None

    # Parse PE header
    img_hdr_pos = nt_hdr_pos + 4
    num_sections, = struct.unpack_from('<H', file_data, img_hdr_pos + 2)
    opt_hdr_pos = img_hdr_pos + 0x14
    opt_hdr_size, = struct.unpack_from('<H', file_data, img_hdr_pos + 0x10)
    nt_hdr_size = 4 + 0x14 + opt_hdr_size
    first_section_hdr_pos = nt_hdr_pos + nt_hdr_size

    cfg_pos = None
    data_pos = None

    # Enumerate PE sections
    pos = first_section_hdr_pos

    for i in range(num_sections):

        s_name = file_data[pos : pos + 8]
        i = s_name.find(0)
        if (i >= 0):
            s_name = s_name[:i]

        s_vsize, s_rva, s_psize, s_pos = \
            struct.unpack_from('<4L', file_data, pos + 8)

        if (s_pos != 0):
            if (s_name == CFG_SECTION_NAME):
                if (min(s_vsize, s_psize) > 12):
                    cfg_pos = s_pos
                    cfg_sec_size = s_vsize
            elif (s_name == DATA_SECTION_NAME):
                data_pos, data_size = s_pos, s_psize

        pos += 0x28

    if cfg_pos is None:
        return None
    if data_pos is None:
        return cfg_pos, None

    # Enumerate encrypted blobs
    num_blobs = 0

    pos = data_pos
    while data_size > 4:

        size, = struct.unpack_from('<L', file_data, pos)
        pos += 4 + size
        data_size -= 4 + size

        if size == 0:
            break

        num_blobs += 1

    helper_code_pos = None

    # Usually, num_blobs = 46
    if (num_blobs >= 20) and (data_size > 4):
        size, = struct.unpack_from('<L', file_data, pos)
        if (size != 0) and (data_size >= size + 4):
            helper_code_pos = pos

    return cfg_pos, helper_code_pos


def extract_helper_code(file_data, pos):
    """Extract helper code"""

    size, = struct.unpack_from('<L', file_data, pos)
    pos += 4
    data = bytearray(file_data[pos : pos + size])

    for i in range(len(data)):
        data[i] ^= HELPER_CODE_XOR_MASK

    return aplib.decompress(data)


def mkdirs(dir):
    """Create directory hierarchy"""

    try:
        os.makedirs(dir)

    except OSError as exception:
        if (exception.errno != errno.EEXIST):
            raise


def save_data_to_file(file_name, data):
    """Save binary data to file."""
    with io.open(file_name, 'wb') as f:
        f.write(data)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

file_name = sys.argv[1]

# Load file data
with io.open(file_name, 'rb') as f:
    file_data = f.read()

cfg_pos = CFG_POS
helper_code_pos = HELPER_CODE_POS
if (cfg_pos is None) or (helper_code_pos is None):

    # Get sample information
    info = get_lb3_info(file_data)
    if info is not None:

        if cfg_pos is None:
            cfg_pos = info[0]
        elif cfg_pos != info[0]:
            print('Warning: Auto-detected cfg data position is %08X.' % info[0])

        if info[1] is None:
            if helper_code_pos is None:
                print('Warning: Unable to find helper code.')
        else:
            if helper_code_pos is None:
                helper_code_pos = info[1]
            elif helper_code_pos != info[1]:
                print('Warning: Auto-detected helper code position is %08X.' %
                      info[1])

    elif cfg_pos is None:
        print('Error: Configuration data not found.')
        sys.exit(1)


# Load hash list
hash_list = load_hash_list('./strings.txt')

# Create destination directory
dest_dir = os.path.abspath(os.path.dirname(file_name)) + '/cfg/'
mkdirs(dest_dir)

if helper_code_pos is not None:
    print('helper code position: %08X' % helper_code_pos)

    # Extract helper code
    helper_code = extract_helper_code(file_data, helper_code_pos)

    save_data_to_file(dest_dir + 'helper_code.bin', helper_code)
    print('helper code saved to file.')

else:
    print('Warning: Data will be decrypted without helper code.')
    helper_code = None

print('cfg data position: %08X' % cfg_pos)

# Extract configuration data
rnd_seed, = struct.unpack_from('<Q', file_data, cfg_pos)
print(('rnd seed: %08X') % rnd_seed)

cfg_pos += 8

pack_cfg_data_size, = struct.unpack_from('<L', file_data, cfg_pos)
print('compressed cfg data size: %d' % pack_cfg_data_size)

cfg_pos += 4

enc_cfg_data = file_data[cfg_pos : cfg_pos + pack_cfg_data_size]

pack_cfg_data = lb3_dec.decrypt(helper_code, enc_cfg_data, rnd_seed)

cfg_data = aplib.decompress(pack_cfg_data)

print('cfg data size: %d' % len(cfg_data))

save_data_to_file(dest_dir + 'cfg_data.bin', cfg_data)
print('cfg data saved to file.')

pos = 0

# RSA public key
rsa_pub_key = cfg_data[pos : pos + RSA_KEY_SIZE]
save_data_to_file(dest_dir + 'rsa_pubkey.bin', rsa_pub_key)
save_data_to_file(dest_dir + 'pub.key',
                  base64.b64encode(b'\1\0\1' + 125 * b'\0' + rsa_pub_key))
print('RSA public key saved to file.')

# Decryption ID
decr_id = binascii.hexlify(rsa_pub_key[:8]).decode().upper()
print('decryption id: \"%s\"' % decr_id)
# GUID
guid = lb3_id.get_uuid_str(rsa_pub_key)
print('guid: \"%s\"' % guid)
# Ransom extension
victim_id = lb3_id.get_victim_id(guid)
print('ransom ext: \"%s\"' % ('.' + victim_id))
# Ransom note name
ransom_note_name = victim_id + '.' + RANSOM_NOTE_NAME
print('ransom note name: \"%s\"' % ransom_note_name)
# bot_id
bot_id = lb3_id.get_bot_id(guid, True)
print('bot_id: \"%s\"' % bot_id)
# Mutex name
mutex_name = lb3_id.get_bot_id(guid, False)
print('mutex name: \"Global\\%s\"' % mutex_name)

pos += RSA_KEY_SIZE

config = {}

bot = {}

# UID
uid = binascii.hexlify(cfg_data[pos : pos + UID_SIZE]).decode()
bot['uid'] = uid
print('uid: \"%s\"' % uid)

pos += UID_SIZE

# AES key
bot['key'] = binascii.hexlify(cfg_data[pos : pos + AES_KEY_SIZE]).decode()

pos += AES_KEY_SIZE

config['bot'] = bot

cfg = {}

# Settings
settings = {}

for stg_name, stg_type in SETTINGS:

    if stg_type == SETTING_BOOL:

        settings[stg_name] = (cfg_data[pos] != 0)
        pos += 1

    elif stg_type == SETTING_WORD:

        settings[stg_name], = struct.unpack_from('<H', cfg_data, pos)
        pos += 2

    elif stg_type == SETTING_ENC_MODE:

        enc_mode = ENC_MODES.get(cfg_data[pos])
        if enc_mode is not None:
            settings[stg_name] = enc_mode
        else:
            settings[stg_name] = cfg_data[pos]
        pos += 1

    else:
        settings[stg_name] = cfg_data[pos]
        pos += 1

cfg['settings'] = settings

# Fields
data_pos = pos

for fld_name, fld_type, fld_enc in FIELDS:

    if fld_type != FIELD_UNKNOWN:

        ofs, = struct.unpack_from('<L', cfg_data, pos)

        fld_data = ''

        if (ofs != 0):

            i = cfg_data.find(0, data_pos + ofs)
            if (i >= 0):
                b64_data = cfg_data[data_pos + ofs : i]
            else:
                b64_data = cfg_data[data_pos + ofs:]

            data = base64.b64decode(b64_data)

            if fld_enc:
                data = lb3_dec.decrypt(helper_code, data, rnd_seed)

            if fld_type == FIELD_HASHLIST:

                for i in range(0, len(data), 4):

                    h, = struct.unpack_from('<L', data, i)
                    if h == 0:
                        break

                    if fld_data != '':
                        fld_data += ';'
                    s = hash_list.get(h)
                    fld_data += s if (s is not None) else ('0x%08X' % h)

            if fld_type == FIELD_STRLIST:

                fld_data = data.decode('utf-16le')
                str_list = list(filter(None, fld_data.split('\0')))
                fld_data = ';'.join(str_list)

            elif fld_type == FIELD_TEXT:

                try:
                    fld_data = data.decode()
                except UnicodeDecodeError:
                    fld_data = data.decode('latin-1')

            if fld_name == 'note':
                save_data_to_file(dest_dir + ransom_note_name, data)
                print('ransom note saved to file.')

        cfg[fld_name] = fld_data

    pos += 4

config['config'] = cfg

# Save configuration data
with io.open(dest_dir + 'config.json', 'w', encoding='utf-8') as f:
    json.dump(config, f, ensure_ascii = False, indent=2)

print('JSON cfg data saved to file.')
