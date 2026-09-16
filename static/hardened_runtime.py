#!/usr/bin/env python3
"""
Hardened Runtime Flags Audit
Check com.apple.security.cs.* flags in code signature and entitlements.
"""

import sys
import subprocess
import plistlib
from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class HardenedRuntimeFlags:
    """Hardened runtime flags from code signature."""
    # Flags that WEAKEN security when TRUE
    allow_jit: bool = False
    allow_unsigned_executable_memory: bool = False
    allow_dyld_environment_variables: bool = False
    disable_library_validation: bool = False
    disable_executable_page_protection: bool = False
    debugger: bool = False
    get_task_allow: bool = False
    
    # Flags that STRENGTHEN security when TRUE (should be present)
    runtime: bool = False  # com.apple.security.cs.runtime
    library_validation: bool = True  # implied by !disable_library_validation


HARDENED_FLAGS = {
    'com.apple.security.cs.allow-jit': 'Allow JIT compilation (weakens)',
    'com.apple.security.cs.allow-unsigned-executable-memory': 'Allow unsigned executable memory (weakens)',
    'com.apple.security.cs.allow-dyld-environment-variables': 'Allow DYLD env vars (weakens)',
    'com.apple.security.cs.disable-library-validation': 'Disable library validation (weakens)',
    'com.apple.security.cs.disable-executable-page-protection': 'Disable executable page protection (weakens)',
    'com.apple.security.cs.debugger': 'Allow debugger attachment (weakens)',
    'com.apple.security.get-task-allow': 'Allow task port access (weakens)',
    'com.apple.security.cs.runtime': 'Hardened runtime enabled (strengthens)',
}


def check_codesign_entitlements(binary_path: str) -> Dict:
    """Extract entitlements via codesign."""
    try:
        result = subprocess.run(
            ['codesign', '-d', '--entitlements', '-', binary_path],
            capture_output=True, text=True, check=True
        )
        # XML plist is in stderr
        xml_start = result.stderr.find('<?xml')
        if xml_start >= 0:
            xml_data = result.stderr[xml_start:].encode()
            return plistlib.loads(xml_data)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        pass
    return {}


def check_codesign_info(binary_path: str) -> Dict:
    """Get codesign info including hardened runtime status."""
    info = {}
    try:
        result = subprocess.run(
            ['codesign', '-d', '-vvv', binary_path],
            capture_output=True, text=True, check=True
        )
        for line in result.stderr.split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                info[key.strip()] = val.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return info


def audit_hardened_runtime(binary_path: str) -> HardenedRuntimeFlags:
    """Audit hardened runtime flags for a binary."""
    flags = HardenedRuntimeFlags()
    
    # Check entitlements
    entitlements = check_codesign_entitlements(binary_path)
    for flag, desc in HARDENED_FLAGS.items():
        if flag in entitlements:
            value = entitlements[flag]
            if 'weakens' in desc:
                setattr(flags, flag.replace('com.apple.security.cs.', '').replace('-', '_'), bool(value))
            elif 'strengthens' in desc:
                flags.runtime = bool(value)
    
    # Check codesign output for runtime flag
    info = check_codesign_info(binary_path)
    if 'runtime' in info.get('flags', '').lower() or 'runtime' in info.get('Authority', '').lower():
        flags.runtime = True
    
    return flags


def print_audit(flags: HardenedRuntimeFlags, binary_path: str):
    """Print audit results."""
    print(f"=== Hardened Runtime Audit: {binary_path} ===")
    print()
    
    print("Security-Weakening Flags (should be FALSE):")
    weaken_flags = [
        ('allow_jit', 'Allow JIT'),
        ('allow_unsigned_executable_memory', 'Allow Unsigned Executable Memory'),
        ('allow_dyld_environment_variables', 'Allow DYLD Env Vars'),
        ('disable_library_validation', 'Disable Library Validation'),
        ('disable_executable_page_protection', 'Disable Executable Page Protection'),
        ('debugger', 'Debugger Attachment'),
        ('get_task_allow', 'Get Task Allow'),
    ]
    
    issues = 0
    for attr, name in weaken_flags:
        value = getattr(flags, attr)
        status = "⚠️  ENABLED" if value else "✓ disabled"
        print(f"  {name:40} {status}")
        if value:
            issues += 1
    
    print()
    print("Security-Strengthening Flags (should be TRUE):")
    strengthen_flags = [
        ('runtime', 'Hardened Runtime'),
    ]
    for attr, name in strengthen_flags:
        value = getattr(flags, attr)
        status = "✓ enabled" if value else "⚠️  MISSING"
        print(f"  {name:40} {status}")
        if not value:
            issues += 1
    
    print()
    print(f"Total issues: {issues}")
    if issues == 0:
        print("✓ All hardened runtime flags correctly configured")
    else:
        print("⚠️  Review the flagged issues above")


def audit_app_bundle(app_path: str):
    """Audit all binaries in an .app bundle."""
    import glob
    binaries = []
    for pattern in ['**/*']:
        for f in glob.glob(f"{app_path}/{pattern}", recursive=True):
            p = Path(f)
            if p.is_file() and not p.suffix and p.name not in ['Info.plist', 'PkgInfo']:
                # Check if it's a Mach-O binary
                try:
                    with open(p, 'rb') as fh:
                        magic = fh.read(4)
                        if magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', 
                                     b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
                            binaries.append(str(p))
                except:
                    pass
    
    print(f"=== App Bundle Audit: {app_path} ===")
    print(f"Found {len(binaries)} Mach-O binaries")
    print()
    
    for binary in binaries:
        flags = audit_hardened_runtime(binary)
        print_audit(flags, binary)
        print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary|.app-bundle>")
        sys.exit(1)
    
    path = sys.argv[1]
    p = Path(path)
    
    if p.suffix == '.app':
        audit_app_bundle(path)
    else:
        flags = audit_hardened_runtime(path)
        print_audit(flags, path)


if __name__ == '__main__':
    main()