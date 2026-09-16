# Mach-O Format Reference

## Header (mach_header / mach_header_64)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | magic | MH_MAGIC (0xfeedface), MH_MAGIC_64 (0xfeedfacf), etc. |
| 4 | 4 | cputype | CPU architecture (7=x86, 0x01000007=x86_64, 12=arm, 0x0100000c=arm64) |
| 8 | 4 | cpusubtype | CPU subtype |
| 12 | 4 | filetype | MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8, etc. |
| 16 | 4 | ncmds | Number of load commands |
| 20 | 4 | sizeofcmds | Total size of load commands |
| 24 | 4 | flags | MH_PIE=0x200000, MH_TWOLEVEL=0x80, etc. |
| 28 | 4 | reserved | 64-bit only |

## Load Commands

| Command | Value | Description |
|---------|-------|-------------|
| LC_SEGMENT | 0x1 | 32-bit segment |
| LC_SYMTAB | 0x2 | Symbol table |
| LC_DYSYMTAB | 0xb | Dynamic symbol table |
| LC_LOAD_DYLIB | 0xc | Load dylib |
| LC_ID_DYLIB | 0xd | Dylib identification |
| LC_SEGMENT_64 | 0x19 | 64-bit segment |
| LC_UUID | 0x1b | UUID |
| LC_CODE_SIGNATURE | 0x1d | Code signature |
| LC_RPATH | 0x1c | Runtime search path |
| LC_DYLD_INFO | 0x22 | Dyld info (rebasing, binding, exports) |
| LC_DYLD_INFO_ONLY | 0x80000022 | Dyld info only |
| LC_MAIN | 0x80000028 | Entry point (LC_UNIXTHREAD replacement) |
| LC_SOURCE_VERSION | 0x2a | Source version |
| LC_DYLD_EXPORTS_TRIE | 0x33 | Exports trie |
| LC_DYLD_CHAINED_FIXUPS | 0x34 | Chained fixups (PAC) |
| LC_BUILD_VERSION | 0x32 | Build version (min OS, SDK) |

## Segment Flags

- SG_HIGHVM (0x1) - High VM
- SG_FVMLIB (0x2) - Fixed VM library
- SG_NORELOC (0x4) - No relocation
- SG_PROTECTED_VERSION_1 (0x8) - Protected version 1

## Section Types

| Type | Value | Description |
|------|-------|-------------|
| S_TYPE_REGULAR | 0x0 | Regular section |
| S_TYPE_ZEROFILL | 0x1 | Zero fill on demand |
| S_TYPE_CSTRING_LITERALS | 0x2 | C string literals |
| S_TYPE_4BYTE_LITERALS | 0x3 | 4-byte literals |
| S_TYPE_8BYTE_LITERALS | 0x4 | 8-byte literals |
| S_TYPE_LITERAL_POINTERS | 0x5 | Literal pointers |
| S_TYPE_NON_LAZY_SYMBOL_POINTERS | 0x6 | Non-lazy symbol pointers |
| S_TYPE_LAZY_SYMBOL_POINTERS | 0x7 | Lazy symbol pointers |
| S_TYPE_SYMBOL_STUBS | 0x8 | Symbol stubs |
| S_TYPE_MOD_INIT_FUNC_POINTERS | 0x9 | Module init func pointers |
| S_TYPE_MOD_TERM_FUNC_POINTERS | 0xa | Module term func pointers |
| S_TYPE_COALESCED | 0xb | Coalesced |
| S_TYPE_GB_ZEROFILL | 0xc | GB zero fill |
| S_TYPE_INTERPOSING | 0xd | Interposing |
| S_TYPE_16BYTE_LITERALS | 0xe | 16-byte literals |
| S_TYPE_DTRACE_DOF | 0xf | DTrace DOF |
| S_TYPE_LAZY_DYLIB_SYMBOL_POINTERS | 0x10 | Lazy dylib symbol pointers |

## Section Attributes

- S_ATTR_PURE_INSTRUCTIONS (0x80000000) - Pure machine instructions
- S_ATTR_NO_TOC (0x40000000) - No TOC
- S_ATTR_STRIP_STATIC_SYMS (0x20000000) - Strip static symbols
- S_ATTR_NO_DEAD_STRIP (0x10000000) - No dead strip
- S_ATTR_LIVE_SUPPORT (0x08000000) - Live support
- S_ATTR_SELF_MODIFYING_CODE (0x04000000) - Self-modifying code
- S_ATTR_DEBUG (0x02000000) - Debug
- S_ATTR_SOME_INSTRUCTIONS (0x00000400) - Some instructions
- S_ATTR_EXT_RELOC (0x00000200) - External relocation
- S_ATTR_LOC_RELOC (0x00000100) - Local relocation

## Common Segment Names

- __PAGEZERO - Zero page (no protections)
- __TEXT - Code and read-only data (r-x)
- __DATA - Read-write data (rw-)
- __LINKEDIT - Link editor data (contains symbols, strings, signatures)
- __OBJC - Objective-C data
- __objc_classlist - Class list
- __objc_methname - Method names
- __objc_selrefs - Selector references
- __objc_protolist - Protocol list
- __objc_classrefs - Class references
- __objc_superrefs - Superclass references
- __objc_ivars - Instance variables
- __DATA_CONST - Read-only data (const)
- __AUTH - Authentication (PAC)
- __AUTH_CONST - Authenticated const

## Code Signature (LC_CODE_SIGNATURE)

The code signature is a CMS signed blob containing:
- CodeDirectory: Hashes of code pages, entitlements
- Requirements: Code requirements
- Entitlements: Embedded entitlements plist
- Signature: Cryptographic signature

## Hardened Runtime Flags (entitlements)

| Flag | Description |
|------|-------------|
| com.apple.security.cs.runtime | Enable hardened runtime |
| com.apple.security.cs.allow-jit | Allow JIT compilation |
| com.apple.security.cs.allow-unsigned-executable-memory | Allow unsigned executable memory |
| com.apple.security.cs.allow-dyld-environment-variables | Allow DYLD env vars |
| com.apple.security.cs.disable-library-validation | Disable library validation |
| com.apple.security.cs.disable-executable-page-protection | Disable executable page protection |
| com.apple.security.cs.debugger | Allow debugger |
| com.apple.security.get-task-allow | Allow task port access (debugging) |

## Pointer Authentication (PAC)

PAC uses chained fixups (LC_DYLD_CHAINED_FIXUPS) to sign pointers.
Keys:
- IA (Instruction Address) - for code pointers
- DA (Data Address) - for data pointers
- GA (Generic Address) - generic

## Dyld Shared Cache

Format: dyld_shared_cache_<arch>
Contains: All system dylibs merged into single file
Extraction: Use dsc_extractor.bundle or dyld_shared_cache_util

## Tools

- `otool` - Object file display
- `nm` - Symbol table
- `codesign` - Code signing
- `dyldinfo` - Dyld info
- `pagestuff` - Page stuff
- `dsymutil` - DWARF debug symbol utility