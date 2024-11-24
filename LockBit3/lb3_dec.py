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

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    HAVE_UNICORN = False
else:
    HAVE_UNICORN = True


# Decrypt helper offset
DECR_HELPER_OFFSET = 0x83


# Emulation
BASE_ADDR = 0x10000
# Stack
STACK_SIZE = 0x10000
STACK_INIT_POS = (STACK_SIZE // 2) & ~0xFF


RND_ADDENDUM = 0x14057B7EF767814F
RND_MULTIPLIER = 0x5851F42D4C957F2D


def decrypt_block_helper(helper_code, seed, n):
    """Decrypt block helper"""

    try:

        # Initialize emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        code_size = (len(helper_code) + 1 + 0xFFFF) & ~0xFFFF
        stack_addr = BASE_ADDR + code_size

        # Map memory for this emulation
        mu.mem_map(BASE_ADDR, code_size + STACK_SIZE)

        end_code_addr = BASE_ADDR + len(helper_code)

        # Write code to memory
        mu.mem_write(BASE_ADDR, helper_code)
        # Add nop to code
        mu.mem_write(end_code_addr, b'\x90')

        stack_pos = stack_addr + STACK_INIT_POS

        # Write function parameters to memory
        # Write n
        mu.mem_write(stack_pos, n.to_bytes(8, byteorder='little'))
        # Write seed
        mu.mem_write(stack_pos + 8, seed.to_bytes(8, byteorder='little'))
        # Write n address
        mu.mem_write(stack_pos - 4, stack_pos.to_bytes(4, byteorder='little'))
        # Write seed address
        mu.mem_write(stack_pos - 8, (stack_pos + 8).to_bytes(4, byteorder='little'))
        # Write return address
        mu.mem_write(stack_pos - 12, end_code_addr.to_bytes(4, byteorder='little'))

        mu.reg_write(UC_X86_REG_ESP, stack_pos - 12)
        mu.reg_write(UC_X86_REG_EBP, stack_pos)

        # Emulate machine code in infinite time
        mu.emu_start(BASE_ADDR + DECR_HELPER_OFFSET, end_code_addr + 1)

        # Get mask
        x0 = mu.reg_read(UC_X86_REG_EAX)
        x1 = mu.reg_read(UC_X86_REG_EDX)

        # Read n value
        n_data = mu.mem_read(stack_pos, 8)

        return ((x1 << 32) | x0), int.from_bytes(n_data, byteorder='little')

    except UcError as e:

        print('Emu Error: %s' % e)
        return None


def make_byte_mask(x):

    mask = b''

    x0 = x & 0xFFFFFFFF
    x1 = x >> 32

    for _ in range(2):

        mask += bytes([x0 & 0xFF])
        x0 >>= 8
        b3 = x1 & 0xFF
        x1 >>= 8
        mask += bytes([x1 & 0xFF])
        mask += bytes([x0 & 0xFF])
        mask += bytes([b3])

        x0 >>= 8
        x1 >>= 8

    return mask


def decrypt1(helper_code, data, seed):
    """Decrypt data using emulation"""

    dec_data = b''

    n = seed

    pos = 0

    size = len(data)

    while (size != 0):

        r = decrypt_block_helper(helper_code, seed, n)
        if r is None:
            return None

        x = make_byte_mask(r[0])
        n = r[1]

        block_size = min(8, size)

        for i in range(block_size):
            dec_data += bytes([data[pos + i] ^ x[i]])

        pos += block_size
        size -= block_size

    return dec_data


def rnd_mul(n, m):

    n0 = n & 0xFFFFFFFF
    n1 = n >> 32
    m0 = m & 0xFFFFFFFF
    m1 = m >> 32

    if (n1 | m1 == 0):
        return (n0 * m0)

    x0 = m0 * n0
    x1 = (m0 * n1 + m1 * n0 + (x0 >> 32)) & 0xFFFFFFFF
    return (x0 & 0xFFFFFFFF) | (x1 << 32)


def decrypt2(data, seed):
    """Decrypt data without using emulation"""

    dec_data = b''

    n = seed

    pos = 0

    size = len(data)

    while (size != 0):

        n = (rnd_mul(n, RND_MULTIPLIER) + RND_ADDENDUM) & 0xFFFFFFFFFFFFFFFF
        x = rnd_mul(seed, n)

        xx = make_byte_mask(x)

        block_size = min(8, size)

        for i in range(block_size):
            dec_data += bytes([data[pos + i] ^ xx[i]])

        pos += block_size
        size -= block_size

    return dec_data


def decrypt(helper_code, data, seed):
    """Decrypt data"""

    if HAVE_UNICORN and (helper_code is not None):
        # Decrypt data using emulation
        return decrypt1(helper_code, data, seed)

    # Decrypt data without using emulation
    return decrypt2(data, seed)



if __name__ == '__main__':
    import sys
    import io
    import os

    if len(sys.argv) != 3:
        print('Usage:', os.path.basename(sys.argv[0]), 'filename seed')
        sys.exit(0)

    file_name = sys.argv[1]
    with io.open(file_name, 'rb') as f:
        data = f.read()

    rnd_seed = int(sys.argv[2], 16)

#    with io.open('helper_code.bin', 'rb') as f:
#        helper_code = f.read()

#    dec_data = decrypt1(helper_code, data, rnd_seed)

    dec_data = decrypt2(data, rnd_seed)

    new_file_name = file_name + '.dec'
    with io.open(new_file_name, 'wb') as f:
        f.write(dec_data)

    print('Done!')
