# Pointer Authentication (PAC) Bypass Techniques Reference

## Overview

Pointer Authentication (PAC) is a hardware feature on ARMv8.3+ (A12+ / iPhone XS+) that signs pointers with a cryptographic MAC (Message Authentication Code) using a secret key. It protects:
- Return addresses (RA)
- Function pointers
- Block pointers
- C++ vtable pointers
- Objective-C method pointers

## PAC Keys

| Key | Purpose | Register |
|-----|---------|----------|
| IA (Instruction Address) | Code pointers (return addresses, function pointers) | APIAKey |
| IB (Instruction Address B) | Secondary code pointers | APIBKey |
| DA (Data Address) | Data pointers (block, vtable, ObjC) | APDAKey |
| DB (Data Address B) | Secondary data pointers | APDBKey |
| GA (Generic Address) | Generic pointers | APGAKey |

## PAC Instructions

### Signing (PAC)
- `PACIA` - Sign with IA key
- `PACIB` - Sign with IB key
- `PACDA` - Sign with DA key
- `PACDB` - Sign with DB key
- `PACGA` - Sign with GA key

### Authentication (AUT)
- `AUTIA` - Authenticate with IA key
- `AUTIB` - Authenticate with IB key
- `AUTDA` - Authenticate with DA key
- `AUTDB` - Authenticate with DB key
- `AUTGA` - Authenticate with GA key

### Stripping (XPAC)
- `XPACIA` - Strip IA PAC
- `XPACIB` - Strip IB PAC
- `XPACDA` - Strip DA PAC
- `XPACDB` - Strip DB PAC
- `XPACGA` - Strip GA PAC

### Combined
- `PACIASP` - Sign return address (SP relative)
- `AUTIASP` - Authenticate return address
- `RETAA` - Return with authentication (IA)
- `RETAB` - Return with authentication (IB)

## Bypass Techniques

### 1. PAC Key Leakage
- **Key extraction**: Read PAC keys from kernel memory (requires kernel exploit)
- **Key derivation**: Derive keys from known values (weak entropy)
- **Side-channel**: Timing/power analysis to extract keys

### 2. PAC Signing Oracle
- **Arbitrary PAC signing**: Find gadget that calls `PACIA`/`PACDA` with controlled input
- **Kernel PAC signing**: Use kernel syscalls that sign pointers
- **Userspace signing**: Use `pac_sign()` if available

### 3. PAC Stripping Gadgets
- **XPAC gadgets**: Find `XPACIA`/`XPACDA` sequences
- **Retab/Retaa**: Use authenticated return gadgets
- **Branch authentication**: Use `BRAA`/`BRAB`/`BLRAA`/`BLRAB`

### 4. Pointer Forgery Without PAC
- **Unsigned pointers**: Find code paths that don't use PAC
- **JOP/ROP without PAC**: Use gadgets before PAC signing
- **Data-only attacks**: Modify non-pointer data

### 5. PAC Bypass via Type Confusion
- **Signed pointer reuse**: Use valid PAC from one pointer type for another
- **Context confusion**: Use IA-signed pointer where DA expected
- **Key confusion**: Use wrong key for authentication

### 6. Chained Fixups Manipulation
- **Dyld chained fixups**: Modify fixup data at runtime
- **Fixup replay**: Replay fixup application with modified data
- **Lazy binding manipulation**: Intercept lazy symbol binding

### 7. JIT / Unsigned Code
- **JIT spraying**: Create executable memory without PAC
- **Unsigned executable memory**: Use `com.apple.security.cs.allow-unsigned-executable-memory`
- **DYLD env vars**: Use `DYLD_INSERT_LIBRARIES` to inject unsigned code

## Gadget Types

### PAC Signing Gadgets
```asm
// Sign with IA key
pacia x16, x17
ret

// Sign with DA key
pacda x16, x17
ret
```

### PAC Stripping Gadgets
```asm
// Strip IA PAC
xpacia x16
ret

// Strip DA PAC
xpacda x16
ret
```

### Authenticated Branch Gadgets
```asm
// Authenticated branch with IA
braa x16, x17

// Authenticated branch with DA
brab x16, x17

// Authenticated branch link with IA
blraa x16, x17

// Authenticated branch link with DA
blrab x16, x17
```

### Return Gadgets
```asm
// Authenticated return (IA)
retaa

// Authenticated return (IB)
retab
```

## Finding Gadgets

### Static Analysis
```bash
# Find PAC instructions in binary
otool -tv binary | grep -E "pacia|pacib|pacda|pacdb|pacga|autia|autib|autda|autdb|autga|xpac"

# Find authenticated branches
otool -tv binary | grep -E "braa|brab|blraa|blrab|retaa|retab"
```

### Dynamic Analysis (Frida)
```javascript
// Scan for PAC gadgets
const modules = Process.enumerateModules();
modules.forEach(m => {
    Memory.scan(m.base, m.size, "pacia x16", (addr, size) => {
        console.log(`PACIA gadget at ${addr} in ${m.name}`);
    });
});
```

### Automated Tools
- `pacfind` - Find PAC gadgets
- `ROPgadget` - ROP gadget finder (with PAC support)
- `pwntools` - ROP/ROPgadget integration

## Mitigations

### Compiler
- `-fptrauth-return-address` - Sign return addresses
- `-fptrauth-function-pointer` - Sign function pointers
- `-fptrauth-block` - Sign block pointers
- `-fptrauth-vtable` - Sign vtable pointers

### Runtime
- **Hardened Runtime**: Enables PAC for all pointers
- **Library Validation**: Prevents unsigned library injection
- **Code Signing**: Requires valid signature for PAC keys

### Kernel
- **PAC Key Isolation**: Per-process PAC keys
- **Key Rotation**: Periodic key rotation
- **Entropy**: Strong key generation

## Research Areas

1. **Cross-process PAC key sharing** - Can keys be shared?
2. **PAC key derivation** - How are keys derived from boot entropy?
3. **Speculative execution** - Can PAC be bypassed via Spectre?
4. **Fault injection** - Can voltage/clock glitching skip PAC?
5. **Side channels** - Timing/power analysis of PAC instructions
6. **JIT interaction** - How does PAC work with JIT compilers?

## Tools

| Tool | Purpose |
|------|---------|
| `otool` | Disassembly |
| `dyldinfo` | Dyld info (chained fixups) |
| `pacfind` | Find PAC gadgets |
| `frida` | Dynamic instrumentation |
| `objection` | iOS exploration |
| `lldb` | Debugging |
| `kmem` | Kernel memory read (with exploit) |

## References

- ARM Architecture Reference Manual (ARMv8.3+)
- Apple Platform Security Guide
- "PAC it up: Towards Pointer Integrity using ARM Pointer Authentication" (Qualcomm)
- "PACMAN: Pointer Authentication Compromised" (MIT CSAIL)
- "PACStack: Hardware-Assisted Stack Protection" (USENIX Security)
- "Pointer Authentication on ARMv8.3" (Apple WWDC)
- Frida PAC bypass scripts
- pwntools ROP with PAC

## Disclaimer

This document is for defensive research and educational purposes only. 
Do not use these techniques against systems you don't own or have explicit authorization to test.
Report findings responsibly through Apple Security Bounty or appropriate channels.