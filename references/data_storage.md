# iOS Data Storage Security Reference

Where sensitive data lives on iOS, how it's protected, and how to verify with the toolkit.

## Keychain Architecture

- **Items**: Generic passwords, internet passwords, keys, certificates — identified by service + account.
- **Access groups**: `keychain-access-groups` entitlement controls which apps share items. `application-identifier` prefix + group name.
- **Protection**: Data Protection class (`kSecAttrAccessible*`) + access control (`kSecAttrAccessControl`) with biometric flags.
- **This-device-only**: `*ThisDeviceOnly` variants prevent backup/migration extraction.

### Keychain Verification (Objection/Frida)

```bash
objection -g com.example.app run ios keychain dump
objection -g com.example.app run ios keychain list
# Check accessibility of each item — flag kSecAttrAccessibleAlways
```

## NSUserDefaults Misuse

- Defaults plist: `~/Library/Preferences/<bundle-id>.plist` — **not encrypted**.
- Common misuse: tokens, passwords, API keys in defaults.
- Verify: `objection ios nsuserdefaults get` then inspect values.

## File System Protection Levels

| Class | Data accessible |
|-------|-----------------|
| `NSFileProtectionNone` | Always, even when locked — **weakest** |
| `NSFileProtectionComplete` | Only while unlocked (default for new apps) |
| `NSFileProtectionCompleteUnlessOpen` | While unlocked or file open |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | After first unlock post-boot |

Default protection is inherited from the provisioning profile's `DataProtectionClass`; explicit `None` is a HIGH finding.

## Sensitive Data Locations

| Location | Backup | Protection | Risk |
|----------|--------|------------|------|
| `Documents/` | iTunes/iCloud | Per-file class | HIGH if secrets stored plaintext |
| `Library/Preferences/*.plist` | iTunes/iCloud | None (until iOS 13; then Complete) | HIGH for secrets |
| `Library/Caches/` | ✗ | None | MEDIUM (rebuildable but readable on jailbreak) |
| `tmp/` | ✗ | None | MEDIUM — clear on termination |
| `Library/Application Support/` | iTunes/iCloud | Per-file | Depends |
| CoreData/SQLite in Documents | iTunes/iCloud | Per-file | HIGH if unencrypted PII |

## SQLite / CoreData

- Plain SQLite (`sqlite3` API, CoreData default): readable via `SELECT` on device or from unencrypted backups.
- SQLCipher: encrypted but check PRAGMA key handling — hardcoded keys are common.
- WAL files (`-wal`, `-shm`): may contain recently written rows after main DB is "cleaned".

## Biometric Integration

- `LAContext` + `kSecAccessControl` = correct pattern (key never leaves enclave).
- `NSFaceIDUsageDescription` missing while using FaceID → app crashes (good) or silently degrades (bad).
- Verify: entitlements + `SecAccessControlCreateWithFlags` strings in binary.

## Pasteboard

- `UIPasteboard.general` is readable by ANY app.
- Sensitive data pasted → exfiltration via other apps.
- iOS 14+ shows paste notifications — mitigates but doesn't prevent.
- Verify: grep binary for `UIPasteboard` and check content handling.

## Screenshot / Snapshot Leakage

- iOS snapshots the app on backgrounding; visible in app switcher without unlock.
- Sensitive screens must mask: `UIApplicationWillResignActive` → cover view, or use `UIApplication.shared.ignoreSnapshotOnNextApplicationLaunch`.
- Verify: check for these API strings in binary.

## Verification Commands (toolkit)

```bash
./ios-wizard static crypto <binary>     # keychain accessibility + protection classes
./ios-wizard static entitlements <.mobileprovision>  # access groups, wildcards
# Dynamic (gadget mode):
objection ios keychain dump
objection ios nsuserdefaults get
objection ios file ls Documents
```

## AI Agent Notes

- `crypto_scan.py` maps `NSFileProtectionNone` → HIGH (category `file-protection`).
- Keychain findings from `kSecAttrAccessibleAlways*` strings carry category `keychain-accessibility`.
- When reporting storage findings, always cite the file path and the protection class as evidence.
- The media-off-limits rule still applies: never open/view actual user data files; inspect metadata only.

## Resources

- Apple: Keychain Services Programming Guide
- Apple: File System Programming Guide — Data Protection
- OWASP MASVS-STORAGE (MSTG-STORAGE-001..008)
