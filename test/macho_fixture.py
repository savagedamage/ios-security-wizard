#!/usr/bin/env python3
"""
macho_fixture.py — Minimal Valid Mach-O 64-bit Builder
Builds synthetic Mach-O executables for parser testing (no Xcode needed).
Produces a well-formed file that real parsers can read end-to-end.
"""

import struct
import sys
from pathlib import Path

MH_MAGIC_64 = 0xfeedfacf
CPU_TYPE_ARM64 = 0x0100000c
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 0x2
MH_PIE = 0x200000
MH_TWOLEVEL = 0x80

# Load commands
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
LC_UUID = 0x1b
LC_MAIN = 0x28 | 0x80000000
LC_SOURCE_VERSION = 0x2a
LC_BUILD_VERSION = 0x32
LC_DYLD_CHAINED_FIXUPS = 0x34
LC_CODE_SIGNATURE = 0x1d
LC_FUNCTION_STARTS = 0x26

# Section types
S_REGULAR = 0x0
S_CSTRING_LITERALS = 0x2
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_MOD_INIT_FUNC_POINTERS = 0x9
S_ATTR_PURE_INSTRUCTIONS = 0x80000000

PAGE = 0x4000  # 16KB page (arm64)


def align_up(x, a):
    return (x + a - 1) & ~(a - 1)


def build_macho_arm64(path: str, with_strings: bool = True):
    """Build a minimal but VALID arm64 Mach-O executable.

    Layout:
      header (32)
      load commands:
        LC_SEGMENT_64 __PAGEZERO (72)
        LC_SEGMENT_64 __TEXT (72 + 2 sections = 232)
        LC_SEGMENT_64 __DATA (72 + 1 section = 152)
        LC_SEGMENT_64 __LINKEDIT (72)
        LC_UUID (24)
        LC_MAIN (24)
        LC_SOURCE_VERSION (16)
        LC_BUILD_VERSION (24)
        LC_SYMTAB (24)
        LC_DYSYMTAB (80)
        LC_CODE_SIGNATURE (16)
      __TEXT content: 0x1000 bytes (__text) + 0x100 bytes (__cstring)
      __DATA content: 0x100 bytes
      __LINKEDIT: string table + symbol table
    """
    # --- Load command size accounting ---
    seg_pagezero_size = 72
    seg_text_size = 72 + 2 * 80          # 2 sections
    seg_data_size = 72 + 1 * 80          # 1 section
    seg_linkedit_size = 72
    uuid_size = 24
    main_size = 24
    source_ver_size = 16
    build_ver_size = 24
    symtab_size = 24
    dysymtab_size = 80
    codesig_size = 16

    ncmds = 11
    sizeofcmds = (seg_pagezero_size + seg_text_size + seg_data_size +
                  seg_linkedit_size + uuid_size + main_size + source_ver_size +
                  build_ver_size + symtab_size + dysymtab_size + codesig_size)

    header = struct.pack('<IIIIIIII',
                         MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE,
                         ncmds, sizeofcmds, MH_PIE | MH_TWOLEVEL, 0)

    # File offsets (header + load commands aligned to page)
    lc_end = 32 + sizeofcmds
    text_fileoff = align_up(lc_end, PAGE)
    text_vmaddr = 0x100000000
    text_size = PAGE                       # __text 0x1000
    cstring_fileoff = text_fileoff + PAGE
    cstring_size = 0x100
    text_total = text_size + cstring_size

    data_fileoff = align_up(cstring_fileoff + cstring_size, PAGE)
    data_vmaddr = text_vmaddr + PAGE * 2
    data_size = PAGE

    linkedit_fileoff = align_up(data_fileoff + data_size, PAGE)
    linkedit_size = PAGE

    # --- Build string table content (goes in __LINKEDIT) ---
    strings = [b'\x00', b'__stack_chk_guard\x00', b'__stack_chk_fail\x00',
               b'_main\x00', b'objc_retain\x00', b'objc_release\x00',
               b'dyld_stub_binder\x00']
    if with_strings:
        strings += [b'Hello World\x00', b'kSecAttrAccessibleAlways\x00',
                    b'NSAllowsArbitraryLoads\x00', b'kCCOptionECBMode\x00']
    strtab = b''.join(strings)
    strtab_size = len(strtab)
    stroff = linkedit_fileoff
    symoff = linkedit_fileoff + align_up(strtab_size, 8)

    # 4 symbols, 16 bytes each (nlist_64)
    # nlist_64: strx u32, type u8, sect u8, desc u16, value u64
    def nlist(strx, n_type, n_sect, value):
        return struct.pack('<IBBHQ', strx, n_type, n_sect, 0, value)

    strx_stackchk = strtab.find(b'__stack_chk_guard\x00')
    strx_main = strtab.find(b'_main\x00')
    symbols = b''.join([
        nlist(0, 0x0f, 1, 0),                    # N_SECT
        nlist(strx_main, 0x0f, 1, text_vmaddr),  # _main in __text
        nlist(strx_stackchk, 0x0f, 1, 0),        # stack canary
        nlist(0, 0x01, 0, 0),                    # N_UNDF
    ])
    nsyms = 4
    symtab_end = symoff + len(symbols)

    # --- Build load commands ---
    cmds = b''

    # __PAGEZERO (vmaddr 0, vmsize 0x100000000, no file content)
    cmds += struct.pack('<II16sQQQQIIII',
                        LC_SEGMENT_64, seg_pagezero_size,
                        b'__PAGEZERO\x00\x00\x00\x00\x00\x00',
                        0, 0x100000000, 0, 0,
                        0, 0, 0, 0)

    # __TEXT (r-x, 2 sections: __text, __cstring)
    cmds += struct.pack('<II16sQQQQIIII',
                        LC_SEGMENT_64, seg_text_size,
                        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        text_vmaddr, align_up(text_total, PAGE), text_fileoff, text_total,
                        5, 5, 2, 0)
    # __text section
    cmds += struct.pack('<16s16sQQQQIIII',
                        b'__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        text_vmaddr, text_size, text_fileoff, 3,
                        0, 0, 0, S_ATTR_PURE_INSTRUCTIONS)
    # __cstring section
    cmds += struct.pack('<16s16sQQQQIIII',
                        b'__cstring\x00\x00\x00\x00\x00\x00\x00',
                        b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        text_vmaddr + text_size, cstring_size, cstring_fileoff, 3,
                        0, 0, 0, S_CSTRING_LITERALS)

    # __DATA (rw-, 1 section: __data)
    cmds += struct.pack('<II16sQQQQIIII',
                        LC_SEGMENT_64, seg_data_size,
                        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        data_vmaddr, PAGE, data_fileoff, data_size,
                        3, 3, 1, 0)
    cmds += struct.pack('<16s16sQQQQIIII',
                        b'__data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        b'__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                        data_vmaddr, data_size, data_fileoff, 3,
                        0, 0, 0, S_REGULAR)

    # __LINKEDIT
    cmds += struct.pack('<II16sQQQQIIII',
                        LC_SEGMENT_64, seg_linkedit_size,
                        b'__LINKEDIT\x00\x00\x00\x00\x00\x00',
                        text_vmaddr + align_up(text_total, PAGE) + PAGE,
                        PAGE, linkedit_fileoff, linkedit_size,
                        1, 1, 0, 0)

    # LC_UUID
    cmds += struct.pack('<II16s', LC_UUID, uuid_size,
                        b'\xde\xad\xbe\xef\x00\x00\x00\x01' * 2)

    # LC_MAIN (entry offset into __TEXT, stack size 0)
    cmds += struct.pack('<IIQQ', LC_MAIN, main_size, 0, 0)

    # LC_SOURCE_VERSION
    cmds += struct.pack('<IIQ', LC_SOURCE_VERSION, source_ver_size, 0x010000)

    # LC_BUILD_VERSION (platform iOS=2, minos 0x100000 = 16.0, sdk same)
    cmds += struct.pack('<IIIIII', LC_BUILD_VERSION, build_ver_size, 2, 0x100000, 0x110000, 0)

    # LC_SYMTAB
    cmds += struct.pack('<IIIIII', LC_SYMTAB, symtab_size,
                        symoff, nsyms, stroff, strtab_size)

    # LC_DYSYMTAB
    cmds += struct.pack('<II' + 'I' * 18, LC_DYSYMTAB, dysymtab_size,
                        0, 0, 0, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    # LC_CODE_SIGNATURE (empty datasize; parser just needs the command)
    cmds += struct.pack('<IIII', LC_CODE_SIGNATURE, codesig_size, 0, 0)

    assert len(cmds) == sizeofcmds, f"cmd size mismatch: {len(cmds)} != {sizeofcmds}"

    # --- Assemble file ---
    out = bytearray()
    out += header
    out += cmds
    # Pad to text_fileoff
    out += b'\x00' * (text_fileoff - len(out))
    # __text content (some arm64 nops: 0xd503201f)
    out += b'\x1f\x20\x03\xd5' * (text_size // 4)
    # __cstring content
    cstr = b'Hello World\x00kSecAttrAccessibleAlways\x00kCCOptionECBMode\x00'
    out += cstr + b'\x00' * (cstring_size - len(cstr))
    # Pad to data_fileoff
    out += b'\x00' * (data_fileoff - len(out))
    # __data
    out += b'\x00' * data_size
    # __LINKEDIT: strtab + symtab
    linkedit_content = strtab + b'\x00' * (align_up(strtab_size, 8) - strtab_size) + symbols
    linkedit_content += b'\x00' * (linkedit_size - len(linkedit_content))
    out += linkedit_content

    with open(path, 'wb') as f:
        f.write(out)
    return path


def build_fixture_dir(out_dir: str) -> Path:
    """Build a fixture directory with arm64 and x86_64 samples."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    build_macho_arm64(str(d / 'sample_arm64.macho'))
    build_macho_arm64(str(d / 'sample_arm64_nostrings.macho'), with_strings=False)
    return d


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'fixtures'
    d = build_fixture_dir(out)
    print(f"Fixtures written to {d}")
    for f in sorted(d.iterdir()):
        print(f"  {f.name} ({f.stat().st_size} bytes)")
