# iOS Cryptography Analysis Reference

Deep reference for iOS crypto APIs, weakness patterns, and how to interpret `crypto_scan.py` output.

## Crypto Layers

| Layer | APIs | Typical Use |
|-------|------|-------------|
| CommonCrypto | `CCCrypt`, `CCCryptorCreate`, `CCKeyDerivationPBKDF`, `CCRandomGenerateBytes`, `CC_SHA256` | Legacy/portable C crypto |
| CryptoKit | `SHA256`, `AES.GCM`, `ChaChaPoly`, `HKDF`, `P256`, `Curve25519` | Modern Swift crypto (iOS 13+) |
| Security | `SecKey*`, `SecRandomCopyBytes`, `SecItemAdd/CopyMatching` | Keys, keychain, secure enclave |
| Secure Enclave | `kSecAttrTokenIDSecureEnclave` | Hardware-backed key storage |

## Weakness Taxonomy (severity per crypto_scan.py)

| Weakness | Signature | Severity | Why |
|----------|-----------|----------|-----|
| ECB mode | `kCCOptionECBMode` | CRITICAL | Identical plaintext blocks → identical ciphertext; pattern leakage |
| Hardcoded key/secret | `"key=", "password=", PEM blocks` | CRITICAL | Extractable from binary → full decryption |
| MD2/MD4 | `CC_MD2`, `CC_MD4` | CRITICAL | Cryptographically broken |
| MD5 | `CC_MD5` | HIGH | Collisions practical; forbidden for security decisions |
| PKCS1 v1.5 padding | `kSecPaddingPKCS1` | HIGH | Bleichenbacher oracle attacks |
| `rand()`/`srand()` | `rand(`, `srand(` | HIGH | Predictable; never for secrets |
| CBC without IV integrity | `kCCModeCBC` | LOW-MEDIUM | Verify random IV + HMAC; CBC alone is malleable |
| `kSecAttrAccessibleAlways` | string in binary | HIGH | Keychain readable while device locked |
| SHA1 | `CC_SHA1` | MEDIUM | Collision attacks practical (SHAttered) |
| No RSA padding | `kSecPaddingNone` | MEDIUM | Textbook RSA unsafe |
| `arc4random` (for secrets) | `arc4random(` | LOW | Not CSPRNG; use SecRandomCopyBytes |
| Fixed IV | `IV = "..."` literals | HIGH | Same key+IV reuse breaks CBC/GCM |

## Keychain Accessibility Classes

| Class | Locked device | After first unlock | This device only | Passcode required |
|-------|--------------|-------------------|------------------|-------------------|
| `kSecAttrAccessibleWhenUnlocked` | ✗ | ✓ | ✗ | ✗ |
| `kSecAttrAccessibleAfterFirstUnlock` | ✗ | ✓ | ✗ | ✗ |
| `kSecAttrAccessibleAlways` | ✓ | ✓ | ✗ | ✗ — **weakest** |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | ✗ | ✓ | ✓ | ✓ — **strongest** |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | ✗ | ✓ | ✓ | ✗ |

Recommendation for secrets: `WhenUnlockedThisDeviceOnly` + `kSecAttrAccessControl` with `.privateKeyUsage` biometric flag.

## Secure Enclave Patterns

| Attribute | Expected value | Purpose |
|-----------|---------------|---------|
| `kSecAttrTokenID` | `kSecAttrTokenIDSecureEnclave` | Force key generation in enclave |
| `kSecAttrAccessControl` | `SecAccessControlCreateWithFlags(WhenUnlockedThisDeviceOnly, .privateKeyUsage, ...)` | Biometric/passcode gate per operation |
| `kSecAttrSynchronizable` | absent | Prevent iCloud sync of private keys |
| `kSecAttrIsPermanent` | `true` | Persist key |

## Detection Signatures (grep/strings)

```bash
strings AppBinary | grep -Ei 'kCCOptionECBMode|CC_MD5|CC_SHA1|rand\(|srand\(|kSecPaddingPKCS1|kSecAttrAccessibleAlways|BEGIN .*PRIVATE KEY'
otool -I AppBinary | grep -E 'CCCrypt|SecKey|SecRandom|arc4random'
```

## Interpreting crypto_scan.py Output

- Findings carry `severity`, `category`, `evidence` (the matched string), and `offset`/`section` when located in `__cstring`/`__const`.
- `possible-md5`/`possible-sha256` (32/64 hex chars) are LOW and informational — many legitimate strings match; only escalate with corroborating context (nearby crypto API imports).
- A binary importing `CCCrypt` alone is INFO; combine with `kCCOptionECBMode` in strings for the CRITICAL.
- CryptoKit `Insecure.*` symbols (SHA1, MD5 in CryptoKit) map to HIGH.

## AI Agent Notes

- `scan_binary()` returns `List[CryptoFinding]`; `dedupe_findings()` collapses by (title, evidence).
- Section-relative evidence: offset is absolute file offset into the section content — add `section.offset` when quoting addresses.
- For app bundles use `scan_app_bundle()` which walks all Mach-O binaries and dedupes across them.
- Severity constants live in `Severity` class; do not invent new categories — extend `REMEDIATION_HINTS` in `report_gen.py` instead.

## Resources

- Apple: Cryptographic Services Guide (developer.apple.com)
- OWASP MSTG Crypto chapter (MASVS-CRYPTO)
- NIST SP 800-57 (key management)
