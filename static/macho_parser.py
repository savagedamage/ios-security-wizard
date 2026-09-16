#!/usr/bin/env python3
"""
Mach-O Parser (stdlib only) — parse headers, load commands, segments, sections, symbols, code signatures.
No external dependencies — pure Python stdlib for portability.
"""

import struct
import sys
from dataclasses import dataclass, field
from typing import BinaryIO, List, Optional, Tuple
from enum import IntEnum


class Magic(IntEnum):
    MH_MAGIC = 0xfeedface       # 32-bit
    MH_CIGAM = 0xcefaedfe       # 32-bit swapped
    MH_MAGIC_64 = 0xfeedfacf    # 64-bit
    MH_CIGAM_64 = 0xcffaedfe    # 64-bit swapped
    FAT_MAGIC = 0xcafebabe      # Universal binary
    FAT_CIGAM = 0xbebafeca      # Universal binary swapped


class CpuType(IntEnum):
    CPU_TYPE_X86 = 7
    CPU_TYPE_X86_64 = 0x01000007
    CPU_TYPE_ARM = 12
    CPU_TYPE_ARM64 = 0x0100000c
    CPU_TYPE_ARM64_32 = 0x0100000e


class FileType(IntEnum):
    MH_OBJECT = 0x1
    MH_EXECUTE = 0x2
    MH_FVMLIB = 0x3
    MH_CORE = 0x4
    MH_PRELOAD = 0x5
    MH_DYLIB = 0x6
    MH_DYLINKER = 0x7
    MH_BUNDLE = 0x8
    MH_DYLIB_STUB = 0x9
    MH_DSYM = 0xa
    MH_KEXT_BUNDLE = 0xb


class LoadCommand(IntEnum):
    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_SYMSEG = 0x3
    LC_THREAD = 0x4
    LC_UNIXTHREAD = 0x5
    LC_LOADFVMLIB = 0x6
    LC_IDFVMLIB = 0x7
    LC_IDENT = 0x8
    LC_FVMFILE = 0x9
    LC_PREPAGE = 0xa
    LC_DYSYMTAB = 0xb
    LC_LOAD_DYLIB = 0xc
    LC_ID_DYLIB = 0xd
    LC_LOAD_DYLINKER = 0xe
    LC_ID_DYLINKER = 0xf
    LC_PREBOUND_DYLIB = 0x10
    LC_ROUTINES = 0x11
    LC_SUB_FRAMEWORK = 0x12
    LC_SUB_UMBRELLA = 0x13
    LC_SUB_CLIENT = 0x14
    LC_SUB_LIBRARY = 0x15
    LC_TWOLEVEL_HINTS = 0x16
    LC_PREBIND_CKSUM = 0x17
    LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
    LC_SEGMENT_64 = 0x19
    LC_ROUTINES_64 = 0x1a
    LC_UUID = 0x1b
    LC_RPATH = 0x1c | 0x80000000
    LC_CODE_SIGNATURE = 0x1d
    LC_SEGMENT_SPLIT_INFO = 0x1e
    LC_REEXPORT_DYLIB = 0x1f | 0x80000000
    LC_LAZY_LOAD_DYLIB = 0x20
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
    LC_LOAD_UPWARD_DYLIB = 0x23 | 0x80000000
    LC_VERSION_MIN_MACOSX = 0x24
    LC_VERSION_MIN_IPHONEOS = 0x25
    LC_FUNCTION_STARTS = 0x26
    LC_DYLD_ENVIRONMENT = 0x27
    LC_MAIN = 0x28 | 0x80000000
    LC_DATA_IN_CODE = 0x29
    LC_SOURCE_VERSION = 0x2a
    LC_DYLIB_CODE_SIGN_DRS = 0x2b
    LC_ENCRYPTION_INFO_64 = 0x2c
    LC_LINKER_OPTION = 0x2d
    LC_LINKER_OPTIMIZATION_HINT = 0x2e
    LC_VERSION_MIN_TVOS = 0x2f
    LC_VERSION_MIN_WATCHOS = 0x30
    LC_NOTE = 0x31
    LC_BUILD_VERSION = 0x32
    LC_DYLD_EXPORTS_TRIE = 0x33
    LC_DYLD_CHAINED_FIXUPS = 0x34


class SegmentFlags(IntEnum):
    SG_HIGHVM = 0x1
    SG_FVMLIB = 0x2
    SG_NORELOC = 0x4
    SG_PROTECTED_VERSION_1 = 0x8


class SectionFlags(IntEnum):
    S_ATTR_PURE_INSTRUCTIONS = 0x80000000
    S_ATTR_NO_TOC = 0x40000000
    S_ATTR_STRIP_STATIC_SYMS = 0x20000000
    S_ATTR_NO_DEAD_STRIP = 0x10000000
    S_ATTR_LIVE_SUPPORT = 0x08000000
    S_ATTR_SELF_MODIFYING_CODE = 0x04000000
    S_ATTR_DEBUG = 0x02000000
    S_ATTR_SOME_INSTRUCTIONS = 0x00000400
    S_ATTR_EXT_RELOC = 0x00000200
    S_ATTR_LOC_RELOC = 0x00000100
    S_TYPE_REGULAR = 0x0
    S_TYPE_ZEROFILL = 0x1
    S_TYPE_CSTRING_LITERALS = 0x2
    S_TYPE_4BYTE_LITERALS = 0x3
    S_TYPE_8BYTE_LITERALS = 0x4
    S_TYPE_LITERAL_POINTERS = 0x5
    S_TYPE_NON_LAZY_SYMBOL_POINTERS = 0x6
    S_TYPE_LAZY_SYMBOL_POINTERS = 0x7
    S_TYPE_SYMBOL_STUBS = 0x8
    S_TYPE_MOD_INIT_FUNC_POINTERS = 0x9
    S_TYPE_MOD_TERM_FUNC_POINTERS = 0xa
    S_TYPE_COALESCED = 0xb
    S_TYPE_GB_ZEROFILL = 0xc
    S_TYPE_INTERPOSING = 0xd
    S_TYPE_16BYTE_LITERALS = 0xe
    S_TYPE_DTRACE_DOF = 0xf
    S_TYPE_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
    S_THREAD_LOCAL_REGULAR = 0x11
    S_THREAD_LOCAL_ZEROFILL = 0x12
    S_THREAD_LOCAL_VARIABLES = 0x13
    S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15


@dataclass
class MachHeader:
    magic: int
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: int = 0  # 64-bit only

    @property
    def is_64bit(self) -> bool:
        return self.magic in (Magic.MH_MAGIC_64, Magic.MH_CIGAM_64)

    @property
    def is_swapped(self) -> bool:
        return self.magic in (Magic.MH_CIGAM, Magic.MH_CIGAM_64, Magic.FAT_CIGAM)

    @property
    def cpu_arch(self) -> str:
        # Check for 64-bit variants first (they have the 0x01000000 bit set)
        if self.cputype & 0x01000000:
            base = self.cputype & 0x00ffffff
            if base == CpuType.CPU_TYPE_X86:
                return "x86_64"
            elif base == CpuType.CPU_TYPE_ARM:
                return "arm64"
            elif base == CpuType.CPU_TYPE_ARM64_32 & 0x00ffffff:
                return "arm64_32"
        else:
            base = self.cputype
        if base == CpuType.CPU_TYPE_X86:
            return "x86"
        elif base == CpuType.CPU_TYPE_X86_64:
            return "x86_64"
        elif base == CpuType.CPU_TYPE_ARM:
            return "arm"
        elif base == CpuType.CPU_TYPE_ARM64:
            return "arm64"
        elif base == CpuType.CPU_TYPE_ARM64_32:
            return "arm64_32"
        return f"unknown(0x{self.cputype:x})"


@dataclass
class LoadCommandHeader:
    cmd: int
    cmdsize: int


@dataclass
class SegmentCommand:
    cmd: int
    cmdsize: int
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int
    sections: List['Section'] = field(default_factory=list)


@dataclass
class Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0  # 64-bit only

    @property
    def section_type(self) -> int:
        return self.flags & 0x000000ff

    @property
    def attributes(self) -> int:
        return self.flags & 0xffff0000


@dataclass
class SymtabCommand:
    cmd: int
    cmdsize: int
    symoff: int
    nsyms: int
    stroff: int
    strsize: int


@dataclass
class DysymtabCommand:
    cmd: int
    cmdsize: int
    ilocalsym: int
    nlocalsym: int
    iextdefsym: int
    nextdefsym: int
    iundefsym: int
    nundefsym: int
    tocoff: int
    ntoc: int
    modtaboff: int
    nmodtab: int
    extrefsymoff: int
    nextrefsyms: int
    indirectsymoff: int
    nindirectsyms: int
    extreloff: int
    nextrel: int
    locreloff: int
    nlocrel: int


@dataclass
class DylibCommand:
    cmd: int
    cmdsize: int
    name_offset: int
    timestamp: int
    current_version: int
    compatibility_version: int
    name: str = ""


@dataclass
class UuidCommand:
    cmd: int
    cmdsize: int
    uuid: bytes

    @property
    def uuid_str(self) -> str:
        return '-'.join([
            self.uuid[0:4].hex(),
            self.uuid[4:6].hex(),
            self.uuid[6:8].hex(),
            self.uuid[8:10].hex(),
            self.uuid[10:16].hex()
        ])


@dataclass
class CodeSignatureCommand:
    cmd: int
    cmdsize: int
    dataoff: int
    datasize: int


@dataclass
class DyldInfoCommand:
    cmd: int
    cmdsize: int
    rebase_off: int
    rebase_size: int
    bind_off: int
    bind_size: int
    weak_bind_off: int
    weak_bind_size: int
    lazy_bind_off: int
    lazy_bind_size: int
    export_off: int
    export_size: int


@dataclass
class DyldExportsTrieCommand:
    cmd: int
    cmdsize: int
    dataoff: int
    datasize: int


@dataclass
class DyldChainedFixupsCommand:
    cmd: int
    cmdsize: int
    dataoff: int
    datasize: int


@dataclass
class BuildVersionCommand:
    cmd: int
    cmdsize: int
    platform: int
    minos: int
    sdk: int
    ntools: int
    tools: List[Tuple[int, int, int]] = field(default_factory=list)


@dataclass
class Symbol:
    n_strx: int
    n_type: int
    n_sect: int
    n_desc: int
    n_value: int
    name: str = ""


class MachOParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.f: BinaryIO = open(filepath, 'rb')
        self.header: Optional[MachHeader] = None
        self.load_commands: List = []
        self.symbols: List[Symbol] = []
        self.strings: bytes = b""
        self._parse()

    def _read_struct(self, fmt: str, offset: Optional[int] = None) -> tuple:
        if offset is not None:
            self.f.seek(offset)
        size = struct.calcsize(fmt)
        data = self.f.read(size)
        if len(data) < size:
            raise EOFError(f"Unexpected EOF reading {fmt} at offset {self.f.tell() - len(data)}")
        return struct.unpack(fmt, data)

    def _read_string(self, offset: int, max_len: int = 256) -> str:
        self.f.seek(offset)
        data = self.f.read(max_len)
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')

    def _parse(self):
        # Read magic first to determine endianness
        magic = struct.unpack('<I', self.f.read(4))[0]
        self.f.seek(0)

        if magic in (Magic.FAT_MAGIC, Magic.FAT_CIGAM):
            self._parse_fat()
            return

        # Magic read little-endian: if we got the CIGAM (byte-swapped) value,
        # the file itself is big-endian and must be parsed as such.
        endian = '>' if magic in (Magic.MH_CIGAM, Magic.MH_CIGAM_64, Magic.FAT_CIGAM) else '<'
        self.endian = endian

        if magic in (Magic.MH_MAGIC, Magic.MH_CIGAM):
            self._parse_header_32()
        elif magic in (Magic.MH_MAGIC_64, Magic.MH_CIGAM_64):
            self._parse_header_64()
        else:
            raise ValueError(f"Unknown magic: 0x{magic:x}")

        self._parse_load_commands()
        self._parse_symbols()

    def _parse_fat(self):
        """Parse universal (fat) binary - just find first Mach-O for now."""
        nfat_arch = struct.unpack('>I', self.f.read(4))[0]
        for _ in range(nfat_arch):
            cputype = struct.unpack('>I', self.f.read(4))[0]
            cpusubtype = struct.unpack('>I', self.f.read(4))[0]
            offset = struct.unpack('>I', self.f.read(4))[0]
            size = struct.unpack('>I', self.f.read(4))[0]
            align = struct.unpack('>I', self.f.read(4))[0]
            # Seek to first architecture and parse it
            self.f.seek(offset)
            self._parse()
            break

    def _parse_header_32(self):
        fmt = f'{self.endian}IIIIIII'
        (magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags) = self._read_struct(fmt)
        self.header = MachHeader(magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags)

    def _parse_header_64(self):
        fmt = f'{self.endian}IIIIIIII'
        (magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved) = self._read_struct(fmt)
        self.header = MachHeader(magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)

    def _parse_load_commands(self):
        if not self.header:
            return
        offset = struct.calcsize(f'{self.endian}IIIIIII' if not self.header.is_64bit else f'{self.endian}IIIIIIII')
        for _ in range(self.header.ncmds):
            self.f.seek(offset)
            cmd, cmdsize = self._read_struct(f'{self.endian}II')
            lc = LoadCommandHeader(cmd, cmdsize)
            self.load_commands.append(lc)
            self._parse_load_command(cmd, cmdsize, offset)
            offset += cmdsize

    def _parse_load_command(self, cmd: int, cmdsize: int, offset: int):
        self.f.seek(offset)
        if cmd == LoadCommand.LC_SEGMENT:
            self._parse_segment_32(offset)
        elif cmd == LoadCommand.LC_SEGMENT_64:
            self._parse_segment_64(offset)
        elif cmd == LoadCommand.LC_SYMTAB:
            self._parse_symtab(offset)
        elif cmd == LoadCommand.LC_DYSYMTAB:
            self._parse_dysymtab(offset)
        elif cmd in (LoadCommand.LC_LOAD_DYLIB, LoadCommand.LC_ID_DYLIB,
                     LoadCommand.LC_LOAD_WEAK_DYLIB, LoadCommand.LC_REEXPORT_DYLIB,
                     LoadCommand.LC_LOAD_UPWARD_DYLIB, LoadCommand.LC_LAZY_LOAD_DYLIB):
            self._parse_dylib(offset)
        elif cmd == LoadCommand.LC_UUID:
            self._parse_uuid(offset)
        elif cmd == LoadCommand.LC_CODE_SIGNATURE:
            self._parse_code_signature(offset)
        elif cmd in (LoadCommand.LC_DYLD_INFO, LoadCommand.LC_DYLD_INFO_ONLY):
            self._parse_dyld_info(offset)
        elif cmd == LoadCommand.LC_DYLD_EXPORTS_TRIE:
            self._parse_dyld_exports_trie(offset)
        elif cmd == LoadCommand.LC_DYLD_CHAINED_FIXUPS:
            self._parse_dyld_chained_fixups(offset)
        elif cmd == LoadCommand.LC_BUILD_VERSION:
            self._parse_build_version(offset)
        elif cmd == LoadCommand.LC_MAIN:
            self._parse_main(offset)
        elif cmd == LoadCommand.LC_SOURCE_VERSION:
            self._parse_source_version(offset)
        elif cmd == LoadCommand.LC_VERSION_MIN_MACOSX:
            self._parse_version_min(offset, "macOS")
        elif cmd == LoadCommand.LC_VERSION_MIN_IPHONEOS:
            self._parse_version_min(offset, "iOS")
        elif cmd == LoadCommand.LC_VERSION_MIN_TVOS:
            self._parse_version_min(offset, "tvOS")
        elif cmd == LoadCommand.LC_VERSION_MIN_WATCHOS:
            self._parse_version_min(offset, "watchOS")
        elif cmd == LoadCommand.LC_FUNCTION_STARTS:
            self._parse_function_starts(offset)
        elif cmd == LoadCommand.LC_DATA_IN_CODE:
            self._parse_data_in_code(offset)
        elif cmd == LoadCommand.LC_RPATH:
            self._parse_rpath(offset)
        # Skip others for brevity

    def _parse_segment_32(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}II16sIIIIIIII'
        data = self._read_struct(fmt)
        seg = SegmentCommand(*data[:11], sections=[])
        seg.segname = data[2].decode('utf-8').rstrip('\x00')
        # Parse sections
        sect_offset = offset + struct.calcsize(fmt)
        for _ in range(seg.nsects):
            self.f.seek(sect_offset)
            sect_fmt = f'{self.endian}16s16sIIIIIIII'
            sect_data = self._read_struct(sect_fmt)
            sect = Section(
                sectname=sect_data[0].decode('utf-8').rstrip('\x00'),
                segname=sect_data[1].decode('utf-8').rstrip('\x00'),
                addr=sect_data[2], size=sect_data[3], offset=sect_data[4],
                align=sect_data[5], reloff=sect_data[6], nreloc=sect_data[7],
                flags=sect_data[8]
            )
            seg.sections.append(sect)
            sect_offset += struct.calcsize(sect_fmt)
        self.load_commands[-1] = seg

    def _parse_segment_64(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}II16sQQQQIIII'
        data = self._read_struct(fmt)
        seg = SegmentCommand(*data[:11], sections=[])
        seg.segname = data[2].decode('utf-8').rstrip('\x00')
        # Parse sections
        sect_offset = offset + struct.calcsize(fmt)
        for _ in range(seg.nsects):
            self.f.seek(sect_offset)
            sect_fmt = f'{self.endian}16s16sQQQQIIII'
            sect_data = self._read_struct(sect_fmt)
            sect = Section(
                sectname=sect_data[0].decode('utf-8').rstrip('\x00'),
                segname=sect_data[1].decode('utf-8').rstrip('\x00'),
                addr=sect_data[2], size=sect_data[3], offset=sect_data[4],
                align=sect_data[5], reloff=sect_data[6], nreloc=sect_data[7],
                flags=sect_data[8],
                reserved1=sect_data[9] if len(sect_data) > 9 else 0,
                reserved2=sect_data[10] if len(sect_data) > 10 else 0,
                reserved3=sect_data[11] if len(sect_data) > 11 else 0
            )
            seg.sections.append(sect)
            sect_offset += struct.calcsize(sect_fmt)
        self.load_commands[-1] = seg

    def _parse_symtab(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIIIII'
        data = self._read_struct(fmt)
        symtab = SymtabCommand(*data)
        self.load_commands[-1] = symtab
        # Read string table
        self.f.seek(symtab.stroff)
        self.strings = self.f.read(symtab.strsize)
        # Read symbols
        self.f.seek(symtab.symoff)
        for _ in range(symtab.nsyms):
            if self.header.is_64bit:
                sym_fmt = f'{self.endian}IBBHQ'
            else:
                sym_fmt = f'{self.endian}IBBHI'
            sym_data = self._read_struct(sym_fmt)
            n_strx, n_type, n_sect, n_desc, n_value = sym_data
            name = ""
            if n_strx < len(self.strings):
                null_idx = self.strings[n_strx:].find(b'\x00')
                if null_idx >= 0:
                    name = self.strings[n_strx:n_strx+null_idx].decode('utf-8', errors='replace')
            self.symbols.append(Symbol(n_strx, n_type, n_sect, n_desc, n_value, name))

    def _parse_dysymtab(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIIIIIIIIIIIIIIIIIII'  # cmd, cmdsize + 18 fields
        data = self._read_struct(fmt)
        self.load_commands[-1] = DysymtabCommand(*data)

    def _parse_dylib(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIIIII'
        data = self._read_struct(fmt)
        dylib = DylibCommand(*data)
        dylib.name = self._read_string(offset + dylib.name_offset)
        self.load_commands[-1] = dylib

    def _parse_uuid(self, offset: int):
        self.f.seek(offset + 8)  # skip cmd, cmdsize
        uuid = self.f.read(16)
        self.load_commands[-1] = UuidCommand(self.load_commands[-1].cmd, self.load_commands[-1].cmdsize, uuid)

    def _parse_code_signature(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQ' if self.header.is_64bit else f'{self.endian}IIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = CodeSignatureCommand(*data)

    def _parse_dyld_info(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQQQQQQQ' if self.header.is_64bit else f'{self.endian}IIIIIIIIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = DyldInfoCommand(*data)

    def _parse_dyld_exports_trie(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQ' if self.header.is_64bit else f'{self.endian}IIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = DyldExportsTrieCommand(*data)

    def _parse_dyld_chained_fixups(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQ' if self.header.is_64bit else f'{self.endian}IIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = DyldChainedFixupsCommand(*data)

    def _parse_build_version(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIIIII'
        data = self._read_struct(fmt)
        cmd, cmdsize, platform, minos, sdk, ntools = data
        tools = []
        for _ in range(ntools):
            tool_fmt = f'{self.endian}III'
            tool_data = self._read_struct(tool_fmt)
            tools.append(tool_data)
        self.load_commands[-1] = BuildVersionCommand(cmd, cmdsize, platform, minos, sdk, ntools, tools)

    def _parse_main(self, offset: int):
        self.f.seek(offset + 8)
        if self.header.is_64bit:
            fmt = f'{self.endian}QQ'
        else:
            fmt = f'{self.endian}II'
        entry_off, stack_size = self._read_struct(fmt)
        self.load_commands[-1] = ('LC_MAIN', entry_off, stack_size)

    def _parse_source_version(self, offset: int):
        self.f.seek(offset + 8)
        version = self._read_struct(f'{self.endian}Q')[0]
        self.load_commands[-1] = ('LC_SOURCE_VERSION', version)

    def _parse_version_min(self, offset: int, name: str):
        self.f.seek(offset + 8)
        version = self._read_struct(f'{self.endian}I')[0]
        sdk = self._read_struct(f'{self.endian}I')[0]
        self.load_commands[-1] = (f'LC_VERSION_MIN_{name.upper()}', version, sdk)

    def _parse_function_starts(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQ' if self.header.is_64bit else f'{self.endian}IIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = ('LC_FUNCTION_STARTS', *data)

    def _parse_data_in_code(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIQQ' if self.header.is_64bit else f'{self.endian}IIII'
        data = self._read_struct(fmt)
        self.load_commands[-1] = ('LC_DATA_IN_CODE', *data)

    def _parse_rpath(self, offset: int):
        self.f.seek(offset)
        fmt = f'{self.endian}IIII'
        data = self._read_struct(fmt)
        rpath = DylibCommand(*data)
        rpath.name = self._read_string(offset + rpath.name_offset)
        self.load_commands[-1] = rpath

    def _parse_symbols(self):
        pass  # Already done in _parse_symtab

    def get_segments(self) -> List[SegmentCommand]:
        return [lc for lc in self.load_commands if isinstance(lc, SegmentCommand)]

    def get_sections(self) -> List[Section]:
        sections = []
        for seg in self.get_segments():
            sections.extend(seg.sections)
        return sections

    def get_dylibs(self) -> List[DylibCommand]:
        return [lc for lc in self.load_commands if isinstance(lc, DylibCommand)]

    def get_code_signature(self) -> Optional[CodeSignatureCommand]:
        for lc in self.load_commands:
            if isinstance(lc, CodeSignatureCommand):
                return lc
        return None

    def get_dyld_info(self) -> Optional[DyldInfoCommand]:
        for lc in self.load_commands:
            if isinstance(lc, DyldInfoCommand):
                return lc
        return None

    def get_dyld_exports_trie(self) -> Optional[DyldExportsTrieCommand]:
        for lc in self.load_commands:
            if isinstance(lc, DyldExportsTrieCommand):
                return lc
        return None

    def get_dyld_chained_fixups(self) -> Optional[DyldChainedFixupsCommand]:
        for lc in self.load_commands:
            if isinstance(lc, DyldChainedFixupsCommand):
                return lc
        return None

    def get_uuid(self) -> Optional[str]:
        for lc in self.load_commands:
            if isinstance(lc, UuidCommand):
                return lc.uuid_str
        return None

    def check_hardened_runtime(self) -> dict:
        """Check hardened runtime flags in code signature."""
        result = {
            'has_code_signature': False,
            'flags': [],
            'hardened_runtime': False,
            'library_validation': False,
            'runtime_exceptions': []
        }
        cs = self.get_code_signature()
        if cs:
            result['has_code_signature'] = True
            # Would need to parse the actual code signature blob for flags
            # This is a placeholder - real implementation parses the SuperBlob
        return result

    def check_pac_markers(self) -> dict:
        """Check for pointer authentication (PAC) markers."""
        result = {
            'has_pac': False,
            'pac_enabled': False,
            'pac_keys': [],
            'chained_fixups': False
        }
        # Check for LC_DYLD_CHAINED_FIXUPS (PAC uses chained fixups)
        if self.get_dyld_chained_fixups():
            result['chained_fixups'] = True
            result['has_pac'] = True
        # Check segment flags for PAC
        for seg in self.get_segments():
            if seg.flags & 0x10000000:  # SG_PROTECTED_VERSION_1 or similar
                result['pac_enabled'] = True
        return result

    def check_pie_stack_canary_arc(self) -> dict:
        """Check for PIE, stack canaries, ARC."""
        result = {
            'pie': False,
            'stack_canary': False,
            'arc': False,
            'nx': False
        }
        if self.header:
            # PIE: MH_PIE flag (0x200000)
            if self.header.flags & 0x200000:
                result['pie'] = True
            # Stack canary: usually detected via __stack_chk_guard symbol
            for sym in self.symbols:
                if '__stack_chk_guard' in sym.name or '__stack_chk_fail' in sym.name:
                    result['stack_canary'] = True
                if 'objc_release' in sym.name or 'objc_retain' in sym.name:
                    result['arc'] = True
            # NX: check segment permissions
            for seg in self.get_segments():
                if seg.initprot & 0x1 and seg.maxprot & 0x2:  # r-x -> rwx possible
                    pass
                if not (seg.maxprot & 0x2):  # no write on code segments
                    result['nx'] = True
        return result

    def print_summary(self):
        if not self.header:
            print("No header parsed")
            return
        h = self.header
        print(f"=== Mach-O Summary: {self.filepath} ===")
        print(f"Architecture: {h.cpu_arch} ({'64-bit' if h.is_64bit else '32-bit'})")
        print(f"File Type: {FileType(h.filetype).name if h.filetype in FileType._value2member_map_ else f'0x{h.filetype:x}'}")
        print(f"Flags: 0x{h.flags:x}")
        print(f"Load Commands: {h.ncmds}")
        print(f"UUID: {self.get_uuid() or 'none'}")
        print()

        print("--- Segments ---")
        for seg in self.get_segments():
            print(f"  {seg.segname:16} vm=0x{seg.vmaddr:x} sz=0x{seg.vmsize:x} fileoff=0x{seg.fileoff:x} filesz=0x{seg.filesize:x} prot={seg.initprot:#x}/{seg.maxprot:#x} flags=0x{seg.flags:x} nsects={seg.nsects}")
            for sect in seg.sections:
                type_name = SectionFlags(sect.section_type).name if sect.section_type in SectionFlags._value2member_map_ else f"0x{sect.section_type:x}"
                attr_name = SectionFlags(sect.attributes).name if sect.attributes in SectionFlags._value2member_map_ else f"0x{sect.attributes:x}"
                print(f"    {sect.sectname:16} addr=0x{sect.addr:x} sz=0x{sect.size:x} off=0x{sect.offset:x} align=2^{sect.align} type={type_name} attr={attr_name}")

        print("\n--- Dylibs ---")
        for dylib in self.get_dylibs():
            print(f"  {dylib.name}")

        print("\n--- Special Load Commands ---")
        for lc in self.load_commands:
            if isinstance(lc, (DyldInfoCommand, DyldExportsTrieCommand, DyldChainedFixupsCommand, BuildVersionCommand)):
                print(f"  {type(lc).__name__}: {lc}")

        print("\n--- Security Features ---")
        hw = self.check_hardened_runtime()
        pac = self.check_pac_markers()
        pie = self.check_pie_stack_canary_arc()
        print(f"  Hardened Runtime: {hw['hardened_runtime']} (has sig: {hw['has_code_signature']})")
        print(f"  PIE: {pie['pie']}")
        print(f"  Stack Canary: {pie['stack_canary']}")
        print(f"  ARC: {pie['arc']}")
        print(f"  NX: {pie['nx']}")
        print(f"  PAC/Chained Fixups: {pac['chained_fixups']}")

        print(f"\n--- Symbols ({len(self.symbols)}) ---")
        # Print interesting symbols
        interesting = [s for s in self.symbols if any(k in s.name for k in
                        ['main', 'objc', 'stack_chk', 'dyld', '_start', 'entry', 'crypt', 'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'ssl', 'tls', 'crypto'])]
        for sym in interesting[:30]:
            print(f"  0x{sym.n_value:x} {sym.name}")
        if len(interesting) > 30:
            print(f"  ... and {len(interesting) - 30} more security-relevant symbols")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <mach-o-file>")
        sys.exit(1)
    parser = MachOParser(sys.argv[1])
    parser.print_summary()


if __name__ == '__main__':
    main()