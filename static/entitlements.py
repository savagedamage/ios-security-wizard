#!/usr/bin/env python3
"""
Entitlements & Provisioning Profile Audit
Parse embedded.mobileprovision (CMS/SignedData), extract entitlements, validate.
"""

import sys
import base64
import plistlib
import subprocess
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path


@dataclass
class ProvisioningProfile:
    path: str
    raw_data: bytes
    plist_data: dict = field(default_factory=dict)
    
    # Parsed fields
    uuid: str = ""
    name: str = ""
    team_id: str = ""
    team_name: str = ""
    app_id: str = ""
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    platform: str = ""
    is_xcode_managed: bool = False
    device_identifiers: List[str] = field(default_factory=list)
    entitlements: Dict[str, Any] = field(default_factory=dict)
    certificates: List[bytes] = field(default_factory=list)
    
    # Derived
    is_expired: bool = False
    days_until_expiry: int = 0
    has_wildcard_keychain: bool = False
    over_privileged: List[str] = field(default_factory=list)
    missing_restrictions: List[str] = field(default_factory=list)


def parse_mobileprovision(path: str) -> ProvisioningProfile:
    """Parse embedded.mobileprovision file (CMS/SignedData)."""
    profile = ProvisioningProfile(path=path)
    
    with open(path, 'rb') as f:
        profile.raw_data = f.read()
    
    # The provisioning profile is a CMS signed payload
    # Use security cms to decode (macOS) or openssl
    try:
        # Try macOS security command first
        result = subprocess.run(
            ['security', 'cms', '-D', '-i', path],
            capture_output=True, check=True
        )
        plist_bytes = result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: try openssl
        try:
            result = subprocess.run(
                ['openssl', 'smime', '-verify', '-inform', 'DER', '-in', path, '-noverify'],
                capture_output=True, check=True
            )
            plist_bytes = result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Last resort: extract plist manually (it's embedded in the CMS)
            plist_bytes = extract_plist_from_cms(profile.raw_data)
    
    try:
        profile.plist_data = plistlib.loads(plist_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse plist from mobileprovision: {e}")
    
    extract_profile_fields(profile)
    analyze_entitlements(profile)
    return profile


def extract_plist_from_cms(data: bytes) -> bytes:
    """Extract plist from CMS blob manually (fallback)."""
    # Find the plist magic bytes
    plist_start = data.find(b'<?xml version="1.0" encoding="UTF-8"?>')
    if plist_start == -1:
        plist_start = data.find(b'bplist00')
    if plist_start == -1:
        raise ValueError("Could not find plist in mobileprovision")
    
    # Find end of plist
    plist_end = data.find(b'</plist>', plist_start)
    if plist_end == -1:
        # Try binary plist end
        plist_end = data.find(b'bplist00', plist_start + 8)
    if plist_end == -1:
        plist_end = len(data)
    else:
        plist_end += 8  # include </plist>
    
    return data[plist_start:plist_end]


def extract_profile_fields(profile: ProvisioningProfile):
    """Extract standard fields from parsed plist."""
    p = profile.plist_data
    
    profile.uuid = p.get('UUID', '')
    profile.name = p.get('Name', '')
    profile.team_id = p.get('TeamIdentifier', [''])[0] if p.get('TeamIdentifier') else ''
    profile.team_name = p.get('TeamName', '')
    profile.app_id = p.get('ApplicationIdentifierPrefix', [''])[0] + '.' + p.get('Entitlements', {}).get('application-identifier', '')
    
    # Dates
    for key, attr in [('CreationDate', 'creation_date'), ('ExpirationDate', 'expiration_date')]:
        if key in p:
            dt = p[key]
            if isinstance(dt, datetime):
                setattr(profile, attr, dt)
    
    profile.platform = p.get('Platform', [''])[0] if p.get('Platform') else ''
    profile.is_xcode_managed = p.get('IsXcodeManaged', False)
    profile.device_identifiers = p.get('ProvisionedDevices', [])
    profile.entitlements = p.get('Entitlements', {})
    
    # Certificates (DER encoded)
    certs = p.get('DeveloperCertificates', [])
    profile.certificates = certs if isinstance(certs, list) else [certs]
    
    # Expiry check
    if profile.expiration_date:
        now = datetime.now(profile.expiration_date.tzinfo) if profile.expiration_date.tzinfo else datetime.now()
        profile.is_expired = now > profile.expiration_date
        profile.days_until_expiry = (profile.expiration_date - now).days


def analyze_entitlements(profile: ProvisioningProfile):
    """Analyze entitlements for security issues."""
    ent = profile.entitlements
    
    # Check keychain access groups
    keychain_groups = ent.get('keychain-access-groups', [])
    if isinstance(keychain_groups, list):
        for group in keychain_groups:
            if group.endswith('.*') or group == '*':
                profile.has_wildcard_keychain = True
                profile.over_privileged.append(f"Wildcard keychain access group: {group}")
    
    # Check for over-privileged entitlements
    risky_entitlements = {
        'com.apple.developer.networking.networkextension': 'Network Extension (VPN/Filter)',
        'com.apple.developer.networking.vpn.api': 'VPN API',
        'com.apple.developer.networking.multicast': 'Multicast Networking',
        'com.apple.developer.bluetooth-peripheral': 'Bluetooth Peripheral',
        'com.apple.developer.bluetooth-central': 'Bluetooth Central',
        'com.apple.developer.usb': 'USB Access',
        'com.apple.developer.nfc.readersession': 'NFC Reader',
        'com.apple.developer.healthkit': 'HealthKit',
        'com.apple.developer.homekit': 'HomeKit',
        'com.apple.developer.maps': 'Maps',
        'com.apple.developer.siri': 'SiriKit',
        'com.apple.developer.payment-pass-provisioning': 'Apple Pay',
        'com.apple.developer.associated-domains': 'Associated Domains (check for wildcards)',
        'com.apple.developer.app-groups': 'App Groups (check for wildcards)',
        'com.apple.developer.ubiquity-container-identifiers': 'iCloud Containers',
        'com.apple.developer.ubiquity-kvstore-identifier': 'iCloud Key-Value',
        'com.apple.security.application-groups': 'App Sandbox Groups',
        'com.apple.security.files.user-selected.read-write': 'Full File Access',
        'com.apple.security.files.downloads.read-write': 'Downloads Access',
        'com.apple.security.files.removable-volumes': 'Removable Volumes',
        'com.apple.security.network.server': 'Network Server',
        'com.apple.security.network.client': 'Network Client',
        'com.apple.security.print': 'Printing',
        'com.apple.security.scripting-targets': 'Scripting Targets',
        'com.apple.security.automation.apple-events': 'Apple Events Automation',
    }
    
    for ent_key, desc in risky_entitlements.items():
        if ent_key in ent:
            value = ent[ent_key]
            if isinstance(value, list) and any(v.endswith('.*') or v == '*' for v in value):
                profile.over_privileged.append(f"Wildcard in {ent_key} ({desc}): {value}")
            elif isinstance(value, bool) and value:
                profile.over_privileged.append(f"Enabled: {ent_key} ({desc})")
            elif isinstance(value, str) and (value.endswith('.*') or value == '*'):
                profile.over_privileged.append(f"Wildcard value in {ent_key} ({desc}): {value}")
    
    # Check hardened runtime flags
    hardened_flags = {
        'com.apple.security.cs.allow-jit': 'Allow JIT',
        'com.apple.security.cs.allow-unsigned-executable-memory': 'Allow Unsigned Executable Memory',
        'com.apple.security.cs.allow-dyld-environment-variables': 'Allow DYLD Env Vars',
        'com.apple.security.cs.disable-library-validation': 'Disable Library Validation',
        'com.apple.security.cs.disable-executable-page-protection': 'Disable Executable Page Protection',
        'com.apple.security.cs.debugger': 'Debugger',
        'com.apple.security.get-task-allow': 'Get Task Allow (debugging)',
    }
    
    for flag, desc in hardened_flags.items():
        if ent.get(flag) is True:
            profile.missing_restrictions.append(f"Hardened runtime relaxed: {flag} ({desc})")
    
    # Check for missing important restrictions
    important_restrictions = {
        'com.apple.security.cs.disable-library-validation': False,
        'com.apple.security.cs.allow-unsigned-executable-memory': False,
        'com.apple.security.cs.allow-dyld-environment-variables': False,
    }
    
    for flag, should_be_false in important_restrictions.items():
        if flag not in ent:
            profile.missing_restrictions.append(f"Missing hardened runtime flag: {flag} (should be false)")


def print_profile(profile: ProvisioningProfile):
    """Print human-readable profile summary."""
    print(f"=== Provisioning Profile: {profile.path} ===")
    print(f"Name: {profile.name}")
    print(f"UUID: {profile.uuid}")
    print(f"Team: {profile.team_name} ({profile.team_id})")
    print(f"App ID: {profile.app_id}")
    print(f"Platform: {profile.platform}")
    print(f"Xcode Managed: {profile.is_xcode_managed}")
    if profile.creation_date:
        print(f"Created: {profile.creation_date}")
    if profile.expiration_date:
        print(f"Expires: {profile.expiration_date} ({'EXPIRED' if profile.is_expired else f'{profile.days_until_expiry} days left'})")
    print(f"Devices: {len(profile.device_identifiers)}")
    print(f"Certificates: {len(profile.certificates)}")
    print()
    
    print("--- Entitlements ---")
    for key, value in sorted(profile.entitlements.items()):
        if isinstance(value, list):
            print(f"  {key}: [{', '.join(str(v) for v in value)}]")
        else:
            print(f"  {key}: {value}")
    print()
    
    if profile.has_wildcard_keychain:
        print("⚠️  WARNING: Wildcard keychain access group detected!")
    
    if profile.over_privileged:
        print("--- Over-Privileged Entitlements ---")
        for issue in profile.over_privileged:
            print(f"  ⚠️  {issue}")
        print()
    
    if profile.missing_restrictions:
        print("--- Hardened Runtime Issues ---")
        for issue in profile.missing_restrictions:
            print(f"  ⚠️  {issue}")
        print()
    
    if profile.is_expired:
        print("⚠️  PROFILE EXPIRED")


def check_embedded_mobileprovision(app_path: str) -> Optional[ProvisioningProfile]:
    """Find and parse embedded.mobileprovision in .app bundle."""
    import glob
    patterns = [
        f"{app_path}/embedded.mobileprovision",
        f"{app_path}/**/embedded.mobileprovision",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        if matches:
            return parse_mobileprovision(matches[0])
    return None


def extract_entitlements_from_binary(binary_path: str) -> Dict[str, Any]:
    """Extract entitlements directly from Mach-O binary (codesign)."""
    try:
        result = subprocess.run(
            ['codesign', '-d', '--entitlements', '-', binary_path],
            capture_output=True, text=True, check=True
        )
        # Output is XML plist to stderr
        plist_start = result.stderr.find('<?xml')
        if plist_start >= 0:
            plist_xml = result.stderr[plist_start:]
            return plistlib.loads(plist_xml.encode())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return {}


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <embedded.mobileprovision|.app-bundle|binary>")
        sys.exit(1)
    
    path = sys.argv[1]
    p = Path(path)
    
    if p.name == 'embedded.mobileprovision' or p.suffix == '.mobileprovision':
        profile = parse_mobileprovision(path)
        print_profile(profile)
    elif p.suffix == '.app':
        profile = check_embedded_mobileprovision(path)
        if profile:
            print_profile(profile)
        else:
            print("No embedded.mobileprovision found in .app bundle")
            # Try binary entitlements
            binaries = list(p.glob('**/*'))
            for bin_path in binaries:
                if bin_path.is_file() and not bin_path.name.endswith(('.plist', '.mobileprovision', '.png', '.jpg', '.json', '.strings')):
                    try:
                        ent = extract_entitlements_from_binary(str(bin_path))
                        if ent:
                            print(f"\n--- Entitlements from {bin_path.name} ---")
                            for k, v in ent.items():
                                print(f"  {k}: {v}")
                            break
                    except:
                        continue
    else:
        # Try as binary
        ent = extract_entitlements_from_binary(path)
        if ent:
            print(f"--- Entitlements from {path} ---")
            for k, v in ent.items():
                print(f"  {k}: {v}")
        else:
            print("Could not extract entitlements")


if __name__ == '__main__':
    main()