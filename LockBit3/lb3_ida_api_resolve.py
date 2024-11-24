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

import io
import os
import idautils
import idaapi


XOR_MASK = 0x10035FFF

LOAD_LIB_AND_IAT_FUNC_EA = 0x405DA0

LOAD_LIB_AND_IAT_FUNC_NAME = 'load_lib_and_IAT'

LOAD_LIB_AND_IAT_FUNC_TYPE = \
    'void __stdcall load_lib_and_IAT(void *pIAT, \
                                     const void *pIT, \
                                     HANDLE hHeap, \
                                     void *pfnHeapAlloc)'


API_HASHES_FILENAME = 'api_hashes.txt'

DELIMS = { ' ', '\t' }


def read_api_hash_list(file_name):

    api_hash_list = {}

    with io.open(file_name, 'rt') as f:

        for line in f:

            s = line.strip()
            i = next((i for i, ch in enumerate(s) if ch in DELIMS), None)
            if (i is None):
                continue

            api_hash = int(s[:i].strip(), 16)
            api_name = s[i + 1:].strip()
            if (api_hash != 0) and (api_name != ''):
                api_hash_list[api_hash] = api_name

    return api_hash_list


def ida_set_name(ea, name):

    res = ida_name.set_name(ea, name,
                            ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

    n = 0

    while (res == 0) and (n < 0xFFFFFFFF):

        res = ida_name.set_name(ea, '%s_%d' % (name, n),
                                ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        n += 1

    return res


def rename_iat_entries(api_hash_list, it_ea, iat_ea):

    it_entry_ea = it_ea
    iat_entry_ea = iat_ea

    while True:

        it_entry_ea += 4
        iat_entry_ea += 4

        api_hash = ida_bytes.get_dword(it_entry_ea)
        if (api_hash == 0xCCCCCCCC):
            break

        api_name = api_hash_list.get(api_hash ^ XOR_MASK)
        if (api_name is not None):

            ida_bytes.del_items(iat_entry_ea, 0, 4)
            ida_bytes.create_data(iat_entry_ea, ida_bytes.FF_DWORD, 4,
                                  BADADDR)

            ida_set_name(iat_entry_ea, api_name)


def get_push_imm_arg_val(arg_ea):

    inst = DecodeInstruction(arg_ea)
    if (inst.itype != idaapi.NN_push) and (inst.ops[0].type != o_imm):
        return None

    return inst.ops[0].value


def rename_iat_entries2(api_hash_list, call_ea):

    arg_addrs = idaapi.get_arg_addrs(call_ea)
    if (arg_addrs is None):
        return False
    iat_ea = get_push_imm_arg_val(arg_addrs[0])
    if (iat_ea is None):
        return False
    it_ea = get_push_imm_arg_val(arg_addrs[1])
    if (it_ea is None):
        return False

    rename_iat_entries(api_hash_list, it_ea, iat_ea)

    return True


print('Loading API function hashes...')
api_hashes_filepath = os.path.join(os.path.dirname(__file__),
                                   API_HASHES_FILENAME)
api_hash_list = read_api_hash_list(api_hashes_filepath)
print(str(len(api_hash_list)) + ' API function hashes loaded.')

ida_name.set_name(LOAD_LIB_AND_IAT_FUNC_EA, LOAD_LIB_AND_IAT_FUNC_NAME)

if SetType(LOAD_LIB_AND_IAT_FUNC_EA, LOAD_LIB_AND_IAT_FUNC_TYPE) == 0:
    raise Exception('Failed to set type of ' + LOAD_LIB_AND_IAT_FUNC_NAME + '.')

auto_wait()

for xref in CodeRefsTo(LOAD_LIB_AND_IAT_FUNC_EA, 1):

    if not rename_iat_entries2(api_hash_list, xref):
        print('%08X: Failed to rename IAT entries.' % xref)
