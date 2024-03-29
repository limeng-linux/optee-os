#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2017, 2020, Linaro Limited
# Copyright (c) 2020-2023, Arm Limited.
#

import argparse
import array
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection
import os
import re
import struct
import uuid
import zlib


def get_args():
    parser = argparse.ArgumentParser(
        description='Converts a Trusted '
        'Application ELF file into a C source file, ready for '
        'inclusion in the TEE binary as an "early TA".')

    parser.add_argument('--out', required=True,
                        help='Name of the output C file')

    parser.add_argument(
        '--ta',
        required=False,
        help='Path to the TA binary. File name has to be: <uuid>.* '
        'such as: 8aaaf200-2450-11e4-abe2-0002a5d5c51b.stripped.elf')

    parser.add_argument(
        '--sp',
        required=False,
        help='Path to the SP binary. File name has to be: <uuid>.* '
        'such as: 8aaaf200-2450-11e4-abe2-0002a5d5c51b.stripped.elf')

    parser.add_argument(
        '--compress',
        dest="compress",
        action="store_true",
        help='Compress the image using the DEFLATE '
        'algorithm')

    parser.add_argument(
        '--manifest',
        dest="manifest",
        required=False,
        help='path to the SP manifest file')

    return parser.parse_args()


def get_name(obj):
    # Symbol or section .name can be a byte array or a string, we want a string
    try:
        name = obj.name.decode()
    except (UnicodeDecodeError, AttributeError):
        name = obj.name
    return name


def ta_get_flags(ta_f):
    with open(ta_f, 'rb') as f:
        elffile = ELFFile(f)

        for s in elffile.iter_sections():
            if isinstance(s, SymbolTableSection):
                for symbol in s.iter_symbols():
                    if symbol.name == 'ta_head':
                        # Get the section containing the symbol
                        s2 = elffile.get_section(symbol.entry['st_shndx'])
                        offs = s2.header['sh_offset'] - s2.header['sh_addr']
                        # ta_head offset into ELF binary
                        offs = offs + symbol.entry['st_value']
                        offs = offs + 20    # Flags offset in ta_head
                        f.seek(offs)
                        flags = struct.unpack('<I', f.read(4))[0]
                        return flags

        # For compatibility with older TAs
        for s in elffile.iter_sections():
            if get_name(s) == '.ta_head':
                return struct.unpack('<16x4xI', s.data()[:24])[0]

        raise Exception('.ta_head section not found')


def sp_get_flags(sp_f):
    with open(sp_f, 'rb') as f:
        try:
            elffile = ELFFile(f)
        except ELFError:
            # Binary format SP, return zero flags
            return 0

        for s in elffile.iter_sections():
            if get_name(s) == '.sp_head':
                return struct.unpack('<16x4xI', s.data()[:24])[0]

        raise Exception('.sp_head section not found')


def dump_bin(f, ts, compress):
    with open(ts, 'rb') as _ts:
        bytes = _ts.read()
        uncompressed_size = len(bytes)
        if compress:
            bytes = zlib.compress(bytes)
        size = len(bytes)

    i = 0
    while i < size:
        if i % 8 == 0:
            f.write('\t\t')
        f.write(hex(bytes[i]) + ',')
        i = i + 1
        if i % 8 == 0 or i == size:
            f.write('\n')
        else:
            f.write(' ')
    return (size, uncompressed_size)


def main():
    args = get_args()
    is_sp = False

    if args.ta is None and args.sp is None:
        raise Exception('The --ta or the --sp flag is required')

    if args.ta is not None and args.sp is not None:
        raise Exception('The --ta and the --sp can\'t be combined')

    if args.ta is not None:
        ts = args.ta
        is_sp = False

    if args.sp is not None:
        ts = args.sp
        is_sp = True

    ts_uuid = uuid.UUID(re.sub(r'\..*', '', os.path.basename(ts)))

    f = open(args.out, 'w')
    f.write('/* Generated from ' + ts + ' by ' +
            os.path.basename(__file__) + ' */\n\n')
    f.write('#include <kernel/embedded_ts.h>\n\n')
    f.write('#include <scattered_array.h>\n\n')
    f.write('const uint8_t ts_bin_' + ts_uuid.hex + '[] = {\n')
    ts_size, ts_uncompressed_size = dump_bin(f, ts, args.compress)
    f.write('};\n')

    if is_sp:

        f.write('#include <kernel/secure_partition.h>\n\n')
        f.write('const uint8_t fdt_bin_' + ts_uuid.hex + '[] = {\n')
        dump_bin(f, args.manifest, False)
        f.write('};\n')
        f.write('SCATTERED_ARRAY_DEFINE_PG_ITEM(sp_images, struct \
                sp_image) = {\n')
        f.write('\t.fdt = fdt_bin_' + ts_uuid.hex + ',\n')

        f.write('. image = {')
        f.write('\t.flags = 0x{:04x},\n'.format(sp_get_flags(ts)))
    else:
        f.write('SCATTERED_ARRAY_DEFINE_PG_ITEM(early_tas, struct \
                embedded_ts) = {\n')
        f.write('\t.flags = 0x{:04x},\n'.format(ta_get_flags(ts)))
    f.write('\t.uuid = {\n')
    f.write('\t\t.timeLow = 0x{:08x},\n'.format(ts_uuid.time_low))
    f.write('\t\t.timeMid = 0x{:04x},\n'.format(ts_uuid.time_mid))
    f.write('\t\t.timeHiAndVersion = ' +
            '0x{:04x},\n'.format(ts_uuid.time_hi_version))
    f.write('\t\t.clockSeqAndNode = {\n')
    csn = '{0:02x}{1:02x}{2:012x}'.format(ts_uuid.clock_seq_hi_variant,
                                          ts_uuid.clock_seq_low, ts_uuid.node)
    f.write('\t\t\t')
    f.write(', '.join('0x' + csn[i:i + 2] for i in range(0, len(csn), 2)))
    f.write('\n\t\t},\n\t},\n')
    f.write('\t.size = sizeof(ts_bin_' + ts_uuid.hex +
            '), /* {:d} */\n'.format(ts_size))
    f.write('\t.ts = ts_bin_' + ts_uuid.hex + ',\n')
    if args.compress:
        f.write('\t.uncompressed_size = '
                '{:d},\n'.format(ts_uncompressed_size))
    if is_sp:
        f.write('}\n')
    f.write('};\n')
    f.close()


if __name__ == "__main__":
    main()
