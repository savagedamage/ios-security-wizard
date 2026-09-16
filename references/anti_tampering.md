# iOS Anti-Tampering & Anti-Debugging Reference

Runtime checks apps use to detect tampering/debugging — and how to detect their presence statically.

## Debugger Detection

| Technique | API | Signature |
|-----------|-----|-----------|
| PT_DENY_ATTACH | `ptrace(PT_DENY_ATTACH, 0, 0, 0)` | `ptrace` import + `0x1f` constant |
| P_TRACED flag | `sysctl(KERN_PROC, KERN_PROC_PID, pid, ...)` reading `kp_proc.p_flag` | `sysctl` import + `KERN_PROC` strings |
| isatty check | `isatty(1)` (stdout attached in debuggers) | `isatty` import |
| SIGSTOP trick | `signal(SIGSTOP)` — debugger hangs unless it swallows | `SIGSTOP` reference |

## Hook Detection

| Technique | API | Signature |
|-----------|-----|-----------|
| IMP comparison | Compare current IMP vs known original addresses | `class_getMethodImplementation`, `method_getImplementation` |
| Substrate presence | `dlsym("MSHookFunction")` non-null | `MSHookFunction` string |
| Frida artifact | Scan memory for `frida-agent`/`gum-js-loop` | `frida` string scan |
| Symbol mismatch | `dladdr(ptr)` returns unexpected module | `dladdr` import |

## Environment Checks

| Var | Risk |
|-----|------|
| `DYLD_INSERT_LIBRARIES` | Injection vector |
| `DYLD_FORCE_FLAT_NAMESPACE` | Interposition |
| `NSZombieEnabled` | Debug mode |
| `OBJC_DEBUG_VERBOSE` | ObjC debug |
| `CFFIXED_USER_HOME` | Sandbox escape |

Detection: `getenv("DYLD_INSERT_LIBRARIES")` non-NULL → suspicious.

## Integrity Checks

- `SecCodeCopyStaticCode` + `SecStaticCodeCheckValidity` — verifies code signature at runtime.
- Embedded hash checks: `CC_SHA256` over `__text` compared to embedded constant.
- `LC_CODE_SIGNATURE` page-hash verification via `SecCodeCheckValidity`.

## Timing-Based Detection

- ptrace timing: measure `syscall(SYS_ptrace, ...)` latency — debuggers add measurable delay.
- Watchdog threads: dedicated thread checks breakpoints on hot paths every N ms.
- `mach_absolute_time` deltas for critical functions.

## Static Detection of Anti-Tampering (toolkit)

```bash
# Binary strings
./ios-wizard static macho <binary>   # symbol table: ptrace, sysctl, dlsym, dladdr imports
strings <binary> | grep -Ei 'ptrace|SIGSTOP|DYLD_INSERT|MSHook|frida|SecStaticCode'

# Entitlements that weaken anti-tampering
./ios-wizard static entitlements <binary>   # get-task-allow, disable-library-validation
```

Symbol table presence of `ptrace`/`sysctl`/`dlsym` alone is INFO; combine with `PT_DENY_ATTACH` constant (0x1f) or `KERN_PROC_PID` strings → HIGH confidence anti-debugging present.

## Counter-Measures (for authorized analysis)

1. **Hook the detection** — Frida `Interceptor.replace(ptrace, new NativeCallback(...))` returning 0.
2. **Patch environment** — clear `DYLD_INSERT_LIBRARIES` at attach time.
3. **Self-patch after launch** — NOP the check after it runs once (needs timing analysis).
4. **Whitelist IMPs** — maintain known-good IMP map; restore if altered.
5. **Binary patch** (offline) — patch the check in the re-signed IPA; re-sign with gadget.

## AI Agent Notes

- When the target contains anti-debugging, warn before attaching Frida: attach may be refused (`PT_DENY_ATTACH`) — use `frida -f` (spawn) instead of attach.
- `crypto_scan.py` will flag embedded hashes (32/64 hex) as LOW `possible-md5/sha256` — these are often integrity-check constants; don't double-report.
- Gadget mode changes the threat model: the app is re-signed with YOUR cert, so signature-based integrity checks will fail by design. Document this in the report's scope section.

## Resources

- Apple: Technical Q&A QA1504 (Mac-only but techniques overlap)
- OWASP MASVS-RESILIENCE (MSTG-RESILIENCE-002..004)
- The Art of Mac Malware (Chapter: debugging/anti-debugging)
