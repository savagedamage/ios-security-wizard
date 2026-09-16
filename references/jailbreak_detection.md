# iOS Jailbreak Detection Reference

Detection techniques, bypass methods, and the multi-indicator assessment model used by `dynamic/jailbreak_check.py`.

## Detection Techniques Taxonomy

### 1. Filesystem Checks

| Path | Tool | Severity |
|------|------|----------|
| `/Applications/Cydia.app` | Cydia | CRITICAL |
| `/Applications/Sileo.app` | Sileo | CRITICAL |
| `/Applications/Zebra.app` | Zebra | CRITICAL |
| `/Applications/Filza.app` | Filza | HIGH |
| `/Library/MobileSubstrate/MobileSubstrate.dylib` | Substrate | CRITICAL |
| `/usr/lib/libsubstitute.dylib` | Substitute | CRITICAL |
| `/usr/lib/libhooker.dylib` | libhooker | CRITICAL |
| `/usr/lib/TweakInject` | unc0ver | CRITICAL |
| `/var/lib/dpkg` | Apt/dpkg | HIGH |
| `/bin/bash` | shell | HIGH |
| `/usr/sbin/sshd` | SSH daemon | HIGH |
| `/etc/ssh/sshd_config` | SSH config | HIGH |
| `/private/var/stash` | stash dir | HIGH |

### 2. Sandbox Escape Checks
- `fork()` succeeds (stock sandbox denies) — HIGH indicator.
- Write test to `/private` — sandboxed apps fail.
- `dlsym(RTLD_DEFAULT, "sandbox_init")` behavior.

### 3. Symbol/Class Detection
- `dlsym` for `MSHookFunction`, `MSFindSymbol`.
- `class_exists("CydiaSubstrate")`, `"SubstrateLoader"`.
- Enumerate loaded modules for `*dylib` in `/usr/lib/TweakInject`.

### 4. Environment Variables

| Var | Meaning | Severity |
|-----|---------|----------|
| `DYLD_INSERT_LIBRARIES` | Injection | CRITICAL |
| `SUBSTRATE_SAFE_MODE` | Substrate safe mode | HIGH |
| `MSSAFE_MODE` | MobileSubstrate safe mode | HIGH |
| `CS_DEBUGGED` | Code-signing debug flag | MEDIUM |

### 5. URL Schemes
- `cydia://` CRITICAL, `sileo://` CRITICAL, `filza://` HIGH, `zbra://` CRITICAL.
- `UIApplication.canOpenURL` probe.

### 6. stat() Checks
- `stat("/Applications/Cydia.app")`, `stat("/Library/MobileSubstrate")`.
- Check link count/ownership anomalies on root binaries.

## Common Bypass Methods (defensive awareness)

1. **Frida hooking** of the detection functions (`NSFileManager.fileExistsAtPath`, `stat`, `access`).
2. **Path spoofing** — return NO for known jailbreak paths.
3. **Objection** `ios jailbreak disable` — patches common detection APIs.
4. **Kernel-level** hiding (checkra1n + rootless) — files not visible at all.

## jailbreak_check.py Model

- Gathers multi-indicator data via Frida (gadget mode): files, substrate classes, env vars, fork(), Frida modules.
- Verdict thresholds:
  - ≥2 CRITICAL → `JAILBROKEN`
  - ≥1 CRITICAL → `LIKELY JAILBROKEN`
  - ≥2 HIGH → `SUSPICIOUS`
  - ≥1 HIGH → `POSSIBLY MODIFIED`
  - else → `CLEAN`

## False Positive Guidance

| Indicator | Why it can be a false positive |
|-----------|-------------------------------|
| `get-task-allow` in entitlements | Normal for dev-signed builds |
| Frida module present | **Expected** in gadget mode (this toolkit's own injection) |
| `/bin/sh` exists | Present on stock iOS — check hash, not presence |
| `fork()` works | Some system processes legitimately fork; verify within app sandbox context |
| Syslog at `/var/log/syslog` | Present on development-fused devices |

**Rule**: require ≥2 independent indicator categories before reporting.

## AI Agent Notes

- `interpret_frida_results()` maps raw gatherer JSON → `Indicator` objects; thresholds live in `print_indicators()`.
- Without device access, `--static-only` prints the checklist; never claim a device is jailbroken from static-only data.
- Corroborate with `pentest/device_baseline.py --check` drift: unexpected `kern.bootargs`/`security.*` sysctl changes strengthen jailbreak evidence.
- Keep jailbreak findings scoped to the tested device; do not generalize to other devices.

## Resources

- OWASP MASVS-RESILIENCE (MSTG-RESILIENCE-001)
- checkra1n/unc0ver documentation (for signature awareness)
- Apple Platform Security Guide
