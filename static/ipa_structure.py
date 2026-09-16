#!/usr/bin/env python3
"""
ipa_structure.py — IPA and .app Bundle Anatomy Analyzer
Extract and analyze IPA structure: bundle layout, Info.plist, extensions,
embedded frameworks, XPC services, code signing files.
"""

import sys
import os
import zipfile
import plistlib
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path


@dataclass
class BundleInfo:
    path: str
    bundle_id: str = ""
    executable: str = ""
    version: str = ""
    short_version: str = ""
    min_os: str = ""
    platform: str = ""
    url_schemes: List[str] = field(default_factory=list)
    queries_schemes: List[str] = field(default_factory=list)
    background_modes: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    xpc_services: List[str] = field(default_factory=list)
    ats_config: Dict = field(default_factory=dict)
    usage_descriptions: Dict = field(default_factory=dict)
    binaries: List[Dict] = field(default_factory=list)
    files: List[Dict] = field(default_factory=list)
    has_provisioning: bool = False
    is_signed: bool = False
    code_signature_files: List[str] = field(default_factory=list)


def extract_ipa(ipa_path: str, output_dir: str) -> Optional[str]:
    """Extract IPA and return path to .app bundle."""
    try:
        with zipfile.ZipFile(ipa_path, 'r') as z:
            z.extractall(output_dir)
    except Exception as e:
        print(f"Error extracting {ipa_path}: {e}")
        return None

    payload = Path(output_dir) / 'Payload'
    if not payload.exists():
        return None
    apps = list(payload.glob('*.app'))
    if not apps:
        return None
    return str(apps[0])


def parse_info_plist(app_path: str) -> Dict:
    """Parse Info.plist."""
    info_plist = Path(app_path) / 'Info.plist'
    if not info_plist.exists():
        return {}
    try:
        with open(info_plist, 'rb') as f:
            return plistlib.load(f)
    except Exception as e:
        print(f"Error parsing Info.plist: {e}")
        return {}


def analyze_bundle(app_path: str) -> BundleInfo:
    """Analyze .app bundle structure."""
    info = BundleInfo(path=app_path)
    plist = parse_info_plist(app_path)

    # Basic fields
    info.bundle_id = plist.get('CFBundleIdentifier', '')
    info.executable = plist.get('CFBundleExecutable', '')
    info.version = plist.get('CFBundleVersion', '')
    info.short_version = plist.get('CFBundleShortVersionString', '')
    info.min_os = plist.get('MinimumOSVersion', '')
    info.platform = plist.get('DTPlatformName', '')

    # URL schemes
    for url_type in plist.get('CFBundleURLTypes', []):
        if isinstance(url_type, dict):
            info.url_schemes.extend(url_type.get('CFBundleURLSchemes', []))

    # Query schemes
    info.queries_schemes = plist.get('LSApplicationQueriesSchemes', [])

    # Background modes
    info.background_modes = plist.get('UIBackgroundModes', [])

    # ATS config
    info.ats_config = plist.get('NSAppTransportSecurity', {})

    # Usage descriptions
    usage_keys = [k for k in plist.keys() if k.endswith('UsageDescription')]
    for key in usage_keys:
        info.usage_descriptions[key] = plist[key]

    # Walk bundle
    app = Path(app_path)
    for root, dirs, files in os.walk(app_path):
        rel_root = Path(root).relative_to(app)
        for fname in files:
            full = Path(root) / fname
            rel = rel_root / fname
            stat = full.stat()
            file_info = {
                'path': str(rel),
                'size': stat.st_size,
                'mode': oct(stat.st_mode & 0o777)
            }
            info.files.append(file_info)

            # Categorize
            if fname == 'Info.plist':
                pass
            elif fname.endswith('.appex'):
                pass  # directories, not files
            elif fname.startswith('embedded') and fname.endswith('.mobileprovision'):
                info.has_provisioning = True
            elif '_CodeSignature' in str(rel_root):
                info.code_signature_files.append(str(rel))

        # Extensions
        for dname in dirs:
            drel = rel_root / dname
            if dname.endswith('.appex'):
                info.extensions.append(str(drel))
            elif dname.endswith('.framework'):
                info.frameworks.append(str(drel))
            elif dname.endswith('.xpc'):
                info.xpc_services.append(str(drel))

    # Check signing
    info.is_signed = len(info.code_signature_files) > 0

    # Find binaries (Mach-O)
    for f in info.files:
        if f['path'] == info.executable or (f['path'].endswith(info.executable)):
            full = app / f['path']
            try:
                with open(full, 'rb') as fh:
                    magic = fh.read(4)
                if magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                             b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                             b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
                    f['is_macho'] = True
                    with open(full, 'rb') as fh:
                        f['sha256'] = hashlib.sha256(fh.read()).hexdigest()
                    info.binaries.append(f)
            except:
                pass

    return info


def analyze_ipa(ipa_path: str, extract_dir: Optional[str] = None) -> BundleInfo:
    """Analyze an IPA file (extract to temp dir if needed)."""
    import tempfile
    tmp = None
    if extract_dir:
        tmp = extract_dir
    else:
        tmp = tempfile.mkdtemp(prefix='ipa_analysis_')

    app_path = extract_ipa(ipa_path, tmp)
    if not app_path:
        print(f"Error: no .app found in {ipa_path}")
        return BundleInfo(path=ipa_path)

    info = analyze_bundle(app_path)
    info.path = ipa_path

    if not extract_dir:
        import shutil
        shutil.rmtree(tmp)

    return info


def print_bundle_report(info: BundleInfo):
    """Print human-readable bundle report."""
    print(f"=== IPA/Bundle Analysis: {info.path} ===")
    print(f"Bundle ID: {info.bundle_id}")
    print(f"Executable: {info.executable}")
    print(f"Version: {info.short_version} (build {info.version})")
    print(f"Min OS: {info.min_os}")
    print(f"Platform: {info.platform}")
    print(f"Signed: {info.is_signed}")
    print(f"Provisioning: {info.has_provisioning}")
    print()

    if info.url_schemes:
        print(f"--- URL Schemes ({len(info.url_schemes)}) ---")
        for s in info.url_schemes:
            print(f"  {s}://")
        print()

    if info.queries_schemes:
        print(f"--- Queried Schemes ({len(info.queries_schemes)}) ---")
        for s in info.queries_schemes:
            print(f"  {s}")
        print()

    if info.background_modes:
        print(f"--- Background Modes ---")
        for m in info.background_modes:
            print(f"  {m}")
        print()

    if info.extensions:
        print(f"--- Extensions ({len(info.extensions)}) ---")
        for e in info.extensions:
            print(f"  {e}")
        print()

    if info.frameworks:
        print(f"--- Frameworks ({len(info.frameworks)}) ---")
        for f in info.frameworks:
            print(f"  {f}")
        print()

    if info.xpc_services:
        print(f"--- XPC Services ({len(info.xpc_services)}) ---")
        for x in info.xpc_services:
            print(f"  {x}")
        print()

    if info.ats_config:
        print(f"--- ATS Config ---")
        print(json.dumps(info.ats_config, indent=2))
        print()

    if info.usage_descriptions:
        print(f"--- Usage Descriptions ---")
        for k, v in info.usage_descriptions.items():
            print(f"  {k}: {v}")
        print()

    if info.binaries:
        print(f"--- Mach-O Binaries ({len(info.binaries)}) ---")
        for b in info.binaries:
            print(f"  {b['path']} ({b['size']} bytes, sha256={b['sha256'][:16]}...)")
        print()

    print(f"--- File Count ---")
    print(f"  Total files: {len(info.files)}")
    print(f"  Code signature files: {len(info.code_signature_files)}")


def export_json(info: BundleInfo, output_path: str):
    """Export analysis as JSON."""
    data = {
        'path': info.path,
        'bundle_id': info.bundle_id,
        'executable': info.executable,
        'version': info.version,
        'short_version': info.short_version,
        'min_os': info.min_os,
        'platform': info.platform,
        'url_schemes': info.url_schemes,
        'queries_schemes': info.queries_schemes,
        'background_modes': info.background_modes,
        'extensions': info.extensions,
        'frameworks': info.frameworks,
        'xpc_services': info.xpc_services,
        'ats_config': info.ats_config,
        'usage_descriptions': info.usage_descriptions,
        'binaries': info.binaries,
        'files': info.files,
        'has_provisioning': info.has_provisioning,
        'is_signed': info.is_signed,
        'code_signature_files': info.code_signature_files,
    }
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"JSON exported to {output_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='IPA/Bundle Anatomy Analyzer')
    parser.add_argument('target', help='Path to .ipa or .app')
    parser.add_argument('-o', '--output', help='Export JSON to file')
    parser.add_argument('--extract-dir', help='Extract IPA to directory (keep extracted)')

    args = parser.parse_args()

    p = Path(args.target)
    if p.suffix == '.ipa':
        info = analyze_ipa(args.target, args.extract_dir)
    elif p.suffix == '.app' or (p.is_dir()):
        info = analyze_bundle(args.target)
    else:
        print("Target must be .ipa or .app")
        sys.exit(1)

    print_bundle_report(info)

    if args.output:
        export_json(info, args.output)


if __name__ == '__main__':
    main()
