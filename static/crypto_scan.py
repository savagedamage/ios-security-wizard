#!/usr/bin/env python3
"""
crypto_scan.py — Crypto API and Keychain Weakness Scanner
Static analysis of binaries for crypto usage patterns and weaknesses.
Detects: CommonCrypto, CryptoKit, Security framework usage, weak algorithms,
hardcoded keys, insecure keychain accessibility classes.
"""

import sys
import re
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path

# Add sibling dir for Mach-O parser
sys.path.insert(0, str(Path(__file__).parent))
from macho_parser import MachOParser


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CryptoFinding:
    severity: str
    category: str
    title: str
    evidence: str  # string/symbol that triggered
    offset: Optional[int] = None
    section: str = ""


# --- Signature tables ---

# CommonCrypto functions
COMMONCRYPTO_FUNCS = {
    'CCCrypt': ('symmetric-encryption', Severity.INFO, 'AES/3DES block cipher'),
    'CCCryptorCreate': ('symmetric-encryption', Severity.INFO, 'Streaming cipher'),
    'CCCryptorCreateWithMode': ('symmetric-encryption', Severity.INFO, 'Cipher with mode'),
    'CCKeyDerivationPBKDF': ('key-derivation', Severity.INFO, 'PBKDF2 key derivation'),
    'CCKeyDerivationHKDF': ('key-derivation', Severity.INFO, 'HKDF key derivation'),
    'CCRandomGenerateBytes': ('rng', Severity.INFO, 'Secure RNG'),
    'CCRandomCopyBytes': ('rng', Severity.INFO, 'Secure RNG'),
    'CC_MD2': ('hash', Severity.CRITICAL, 'MD2 - cryptographically broken'),
    'CC_MD4': ('hash', Severity.CRITICAL, 'MD4 - cryptographically broken'),
    'CC_MD5': ('hash', Severity.HIGH, 'MD5 - weak hash'),
    'CC_SHA1': ('hash', Severity.MEDIUM, 'SHA1 - collision attacks practical'),
    'CC_SHA256': ('hash', Severity.INFO, 'SHA-256 - secure'),
    'CC_SHA384': ('hash', Severity.INFO, 'SHA-384 - secure'),
    'CC_SHA512': ('hash', Severity.INFO, 'SHA-512 - secure'),
    'CCCryptorGCM': ('aead', Severity.INFO, 'GCM authenticated encryption'),
    'CCECCryptor': ('asymmetric', Severity.INFO, 'Elliptic curve crypto'),
    'CCRSACryptor': ('asymmetric', Severity.INFO, 'RSA crypto'),
}

# Security framework
SECURITY_FUNCS = {
    'SecKeyEncrypt': ('asymmetric', Severity.INFO, 'RSA/EC key encryption'),
    'SecKeyDecrypt': ('asymmetric', Severity.INFO, 'RSA/EC key decryption'),
    'SecKeyCreateRandomKey': ('key-management', Severity.INFO, 'Key generation'),
    'SecKeyCopyPublicKey': ('key-management', Severity.INFO, 'Key export'),
    'SecRandomCopyBytes': ('rng', Severity.INFO, 'Secure RNG'),
    'SecKeychainAddItem': ('keychain', Severity.INFO, 'Keychain add'),
    'SecItemAdd': ('keychain', Severity.INFO, 'Keychain add'),
    'SecItemCopyMatching': ('keychain', Severity.INFO, 'Keychain query'),
    'SecItemUpdate': ('keychain', Severity.INFO, 'Keychain update'),
    'SecItemDelete': ('keychain', Severity.INFO, 'Keychain delete'),
}

# Weak patterns in strings
WEAK_STRING_PATTERNS = [
    (re.compile(rb'kSecAttrAccessibleAlways(?!ThisDeviceOnly)', re.IGNORECASE),
     Severity.HIGH, 'keychain-accessibility',
     'Keychain accessible even when device locked (kSecAttrAccessibleAlways)'),
    (re.compile(rb'kSecAttrAccessibleAlwaysThisDeviceOnly', re.IGNORECASE),
     Severity.MEDIUM, 'keychain-accessibility',
     'Keychain accessible when locked, this-device-only'),
    (re.compile(rb'kSecAttrAccessibleAfterFirstUnlock', re.IGNORECASE),
     Severity.LOW, 'keychain-accessibility',
     'Keychain accessible after first unlock'),
    (re.compile(rb'NSFileProtectionNone', re.IGNORECASE),
     Severity.HIGH, 'file-protection',
     'Files readable without passcode (NSFileProtectionNone)'),
    (re.compile(rb'NSAllowsArbitraryLoads.*?YES|NSAllowsArbitraryLoads', re.IGNORECASE),
     Severity.HIGH, 'ats',
     'ATS allows arbitrary loads (HTTP allowed)'),
    (re.compile(rb'NSExceptionAllowsInsecureHTTPLoads', re.IGNORECASE),
     Severity.MEDIUM, 'ats',
     'ATS exception allows insecure HTTP'),
    (re.compile(rb'arc4random(?!_uniform)', re.IGNORECASE),
     Severity.LOW, 'rng',
     'arc4random used (not cryptographic if used for secrets)'),
    (re.compile(rb'rand\(\)', re.IGNORECASE),
     Severity.HIGH, 'rng',
     'rand() used - not cryptographically secure'),
    (re.compile(rb'srand\(', re.IGNORECASE),
     Severity.HIGH, 'rng',
     'srand() used - predictable seeding'),
    (re.compile(rb'kCCOptionECBMode', re.IGNORECASE),
     Severity.CRITICAL, 'encryption-mode',
     'ECB mode encryption - pattern leakage'),
    (re.compile(rb'kCCModeCBC', re.IGNORECASE),
     Severity.LOW, 'encryption-mode',
     'CBC mode (check IV handling)'),
    (re.compile(rb'kCCModeCTR', re.IGNORECASE),
     Severity.LOW, 'encryption-mode',
     'CTR mode (check counter uniqueness)'),
    (re.compile(rb'kSecPaddingNone', re.IGNORECASE),
     Severity.MEDIUM, 'encryption-padding',
     'No padding on RSA (check for proper OAEP)'),
    (re.compile(rb'kSecPaddingPKCS1\b', re.IGNORECASE),
     Severity.HIGH, 'encryption-padding',
     'PKCS1 v1.5 padding (Bleichenbacher attack)'),
    (re.compile(rb'kSecPaddingOAEP', re.IGNORECASE),
     Severity.INFO, 'encryption-padding',
     'OAEP padding (secure)'),
]

# Hardcoded key detection patterns
KEY_PATTERNS = [
    (re.compile(rb'(?:private\s*key|secret\s*key|api\s*key|api_secret|access\s*key|auth\s*token|password|passphrase|credential)\s*[=:]\s*["\']', re.IGNORECASE),
     Severity.CRITICAL, 'hardcoded-secret',
     'Hardcoded key/secret/password in binary'),
    (re.compile(rb'[a-fA-F0-9]{32}'),
     Severity.LOW, 'possible-md5',
     '32-hex string (possible MD5 hash)'),
    (re.compile(rb'[a-fA-F0-9]{64}'),
     Severity.LOW, 'possible-sha256',
     '64-hex string (possible SHA256 hash/key)'),
    (re.compile(rb'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE),
     Severity.CRITICAL, 'hardcoded-secret',
     'Embedded private key PEM'),
]

# CryptoKit symbols (Swift mangled)
CRYPTOKIT_SYMBOLS = {
    'CryptoKit': ('cryptokit', Severity.INFO, 'CryptoKit usage (Swift crypto)'),
    'AES.GCM': ('aead', Severity.INFO, 'AES-GCM'),
    'ChaChaPoly': ('aead', Severity.INFO, 'ChaCha20-Poly1305'),
    'HKDF': ('key-derivation', Severity.INFO, 'HKDF'),
    'SHA256': ('hash', Severity.INFO, 'SHA-256'),
    'SHA512': ('hash', Severity.INFO, 'SHA-512'),
    'P256': ('asymmetric', Severity.INFO, 'NIST P-256'),
    'P384': ('asymmetric', Severity.INFO, 'NIST P-384'),
    'Curve25519': ('asymmetric', Severity.INFO, 'Curve25519'),
    'Insecure': ('weakness-marker', Severity.HIGH, 'CryptoKit Insecure namespace (weak algorithm)'),
}


def scan_binary(binary_path: str) -> List[CryptoFinding]:
    """Scan a Mach-O binary for crypto patterns."""
    findings = []

    try:
        parser = MachOParser(binary_path)
    except Exception as e:
        print(f"  [error] could not parse {binary_path}: {e}")
        return findings

    # Scan imported symbols
    symbol_names = {s.name for s in parser.symbols}
    for func, (cat, sev, desc) in {**COMMONCRYPTO_FUNCS, **SECURITY_FUNCS}.items():
        if func in symbol_names:
            findings.append(CryptoFinding(
                severity=sev, category=cat,
                title=f"Crypto API: {func} — {desc}",
                evidence=func
            ))

    # Scan for CryptoKit symbols
    for sym in symbol_names:
        for ck_sym, (cat, sev, desc) in CRYPTOKIT_SYMBOLS.items():
            if ck_sym in sym:
                findings.append(CryptoFinding(
                    severity=sev, category=cat,
                    title=f"CryptoKit: {ck_sym} — {desc}",
                    evidence=sym
                ))

    # Scan string sections for weak patterns
    for sect in parser.get_sections():
        if sect.sectname in ('__cstring', '__cfstring', '__ustring', '__const'):
            try:
                parser.f.seek(sect.offset)
                data = parser.f.read(sect.size)
            except Exception:
                continue

            for pattern, sev, cat, desc in WEAK_STRING_PATTERNS:
                if sev is None:
                    continue
                for match in pattern.finditer(data):
                    findings.append(CryptoFinding(
                        severity=sev, category=cat,
                        title=desc,
                        evidence=match.group(0)[:64].decode('utf-8', errors='replace'),
                        offset=sect.offset + match.start(),
                        section=sect.sectname
                    ))

            # Key/secret patterns
            for pattern, sev, cat, desc in KEY_PATTERNS:
                for match in pattern.finditer(data):
                    findings.append(CryptoFinding(
                        severity=sev, category=cat,
                        title=desc,
                        evidence=match.group(0)[:64].decode('utf-8', errors='replace'),
                        offset=sect.offset + match.start(),
                        section=sect.sectname
                    ))

    return findings


def dedupe_findings(findings: List[CryptoFinding]) -> List[CryptoFinding]:
    """Dedupe findings by title+evidence."""
    seen = set()
    result = []
    for f in findings:
        key = (f.title, f.evidence)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def scan_app_bundle(app_path: str) -> List[CryptoFinding]:
    """Scan all binaries in an app bundle."""
    import os
    findings = []
    app = Path(app_path)

    for root, dirs, files in os.walk(app_path):
        for fname in files:
            full = Path(root) / fname
            if fname.endswith(('.dylib', '.framework')) or full.suffix in ('.dylib',):
                pass
            try:
                with open(full, 'rb') as fh:
                    magic = fh.read(4)
                if magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                             b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
                    print(f"  Scanning: {full.relative_to(app)}")
                    findings.extend(scan_binary(str(full)))
            except (OSError, IOError):
                continue

    return dedupe_findings(findings)


def print_findings(findings: List[CryptoFinding], target: str):
    """Print findings grouped by severity."""
    print(f"=== Crypto Scan: {target} ===")
    print(f"Findings: {len(findings)}")
    print()

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in order:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        print(f"--- {sev} ({len(sev_findings)}) ---")
        for f in sev_findings:
            loc = f" @0x{f.offset:x}" if f.offset else ""
            sec = f" [{f.section}]" if f.section else ""
            print(f"  [{f.category}] {f.title}")
            print(f"    Evidence: {f.evidence[:60]}{loc}{sec}")
        print()


def export_json(findings: List[CryptoFinding], output_path: str):
    """Export findings as JSON."""
    import json
    data = [{
        'severity': f.severity,
        'category': f.category,
        'title': f.title,
        'evidence': f.evidence,
        'offset': f.offset,
        'section': f.section,
    } for f in findings]
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"JSON exported to {output_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Crypto API and weakness scanner')
    parser.add_argument('target', help='Path to Mach-O binary or .app bundle')
    parser.add_argument('-o', '--output', help='Export JSON to file')
    parser.add_argument('--quiet', action='store_true', help='Only show findings, no scan progress')

    args = parser.parse_args()

    p = Path(args.target)
    if p.is_dir() or p.suffix == '.app':
        findings = scan_app_bundle(args.target)
    else:
        findings = scan_binary(args.target)

    findings = dedupe_findings(findings)
    print_findings(findings, args.target)

    if args.output:
        export_json(findings, args.output)


if __name__ == '__main__':
    main()
