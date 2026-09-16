#!/usr/bin/env python3
"""
Frida Gadget Injection Helpers for iOS (no jailbreak)
Re-sign IPA with Frida gadget, manage gadget configuration.
"""

import sys
import subprocess
import tempfile
import shutil
import os
import plistlib
from pathlib import Path
from typing import Optional, List


def check_objection() -> bool:
    """Check if objection is available."""
    try:
        subprocess.run(['objection', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_frida() -> bool:
    """Check if frida is available."""
    try:
        subprocess.run(['frida', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def patch_ipa_with_gadget(ipa_path: str, output_path: str, 
                           codesign_identity: str = None,
                           provisioning_profile: str = None,
                           bundle_id: str = None) -> bool:
    """Patch IPA with Frida gadget using objection."""
    if not check_objection():
        print("Error: objection not found. Install with: pip install objection")
        return False
    
    cmd = ['objection', 'patchipa', '-s', ipa_path, '-o', output_path]
    
    if codesign_identity:
        cmd.extend(['--codesign-identity', codesign_identity])
    if provisioning_profile:
        cmd.extend(['--provisioning-profile', provisioning_profile])
    if bundle_id:
        cmd.extend(['--bundle-id', bundle_id])
    
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"Successfully patched: {output_path}")
            return True
        else:
            print(f"Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("Error: Timeout patching IPA")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def extract_ipa(ipa_path: str, output_dir: str) -> bool:
    """Extract IPA to directory."""
    try:
        subprocess.run(['unzip', '-q', ipa_path, '-d', output_dir], check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def find_payload_app(extracted_dir: str) -> Optional[str]:
    """Find the .app bundle in extracted IPA."""
    payload_dir = Path(extracted_dir) / 'Payload'
    if not payload_dir.exists():
        return None
    
    apps = list(payload_dir.glob('*.app'))
    if apps:
        return str(apps[0])
    return None


def get_bundle_id(app_path: str) -> Optional[str]:
    """Get bundle identifier from Info.plist."""
    info_plist = Path(app_path) / 'Info.plist'
    if info_plist.exists():
        try:
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
                return plist.get('CFBundleIdentifier')
        except:
            pass
    return None


def resign_app(app_path: str, codesign_identity: str, 
               provisioning_profile: str = None,
               entitlements: str = None) -> bool:
    """Re-sign an .app bundle."""
    cmd = ['codesign', '-f', '-s', codesign_identity]
    
    if provisioning_profile:
        # Copy provisioning profile to app
        import shutil
        shutil.copy(provisioning_profile, Path(app_path) / 'embedded.mobileprovision')
    
    if entitlements:
        cmd.extend(['--entitlements', entitlements])
    
    # Deep sign (sign all nested binaries)
    cmd.extend(['--deep', '--timestamp', '--options', 'runtime', app_path])
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Codesign failed: {e.stderr}")
        return False


def create_gadget_config(app_path: str, config: dict) -> bool:
    """Create FridaGadget.config file."""
    config_path = Path(app_path) / 'FridaGadget.config'
    import json
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error writing config: {e}")
        return False


def default_gadget_config() -> dict:
    """Default Frida gadget configuration."""
    return {
        "interaction": {
            "type": "listen",
            "address": "0.0.0.0",
            "port": 27042,
            "on_load": "resume"
        },
        "tls": {
            "enabled": False
        },
        "logging": {
            "level": "info",
            "file": "/tmp/frida-gadget.log"
        }
    }


def inject_gadget_dylib(app_path: str, gadget_dylib: str, 
                        codesign_identity: str) -> bool:
    """Inject FridaGadget.dylib into app binary."""
    # Find main binary
    app_binary = None
    for f in Path(app_path).iterdir():
        if f.is_file() and not f.suffix:
            try:
                with open(f, 'rb') as fh:
                    magic = fh.read(4)
                    if magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                                 b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
                        app_binary = f
                        break
            except:
                pass
    
    if not app_binary:
        print("Could not find main binary in app")
        return False
    
    # Copy gadget dylib to Frameworks
    frameworks_dir = Path(app_path) / 'Frameworks'
    frameworks_dir.mkdir(exist_ok=True)
    
    gadget_name = 'FridaGadget.dylib'
    target_dylib = frameworks_dir / gadget_name
    shutil.copy(gadget_dylib, target_dylib)
    
    # Add load command to main binary (using insert_dylib or similar)
    try:
        subprocess.run([
            'insert_dylib', '--inplace', 
            f'@executable_path/Frameworks/{gadget_name}',
            str(app_binary)
        ], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("insert_dylib not found. Install: brew install insert_dylib")
        return False
    
    # Re-sign the modified binary
    return resign_app(app_path, codesign_identity)


def build_and_sign_gadget_ipa(ipa_path: str, output_path: str,
                               codesign_identity: str,
                               provisioning_profile: str = None,
                               bundle_id: str = None) -> bool:
    """Full pipeline: extract, inject gadget, re-sign, repackage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Extract
        extract_dir = Path(tmpdir) / 'extracted'
        if not extract_ipa(ipa_path, str(extract_dir)):
            print("Failed to extract IPA")
            return False
        
        # Find app
        app_path = find_payload_app(str(extract_dir))
        if not app_path:
            print("Could not find .app in IPA")
            return False
        
        # Determine bundle ID
        if not bundle_id:
            bundle_id = get_bundle_id(app_path)
        if not bundle_id:
            print("Could not determine bundle ID")
            return False
        
        print(f"Bundle ID: {bundle_id}")
        
        # Download/get FridaGadget.dylib for iOS
        gadget_dylib = download_frida_gadget_ios(tmpdir)
        if not gadget_dylib:
            print("Failed to get FridaGadget.dylib")
            return False
        
        # Inject gadget
        if not inject_gadget_dylib(app_path, gadget_dylib, codesign_identity):
            print("Failed to inject gadget")
            return False
        
        # Create config
        create_gadget_config(app_path, default_gadget_config())
        
        # Re-sign entire app
        if not resign_app(app_path, codesign_identity, provisioning_profile):
            print("Failed to re-sign app")
            return False
        
        # Repackage IPA
        payload_dir = Path(app_path).parent
        subprocess.run(['zip', '-r', output_path, 'Payload'], 
                       cwd=str(extract_dir), check=True)
        
        print(f"Successfully created gadget IPA: {output_path}")
        return True


def download_frida_gadget_ios(tmpdir: str) -> Optional[str]:
    """Download FridaGadget.dylib for iOS arm64."""
    import urllib.request
    import json
    
    # Get latest Frida release
    try:
        with urllib.request.urlopen('https://api.github.com/repos/frida/frida/releases/latest') as resp:
            release = json.load(resp)
        
        for asset in release['assets']:
            if 'frida-gadget' in asset['name'] and 'ios' in asset['name'] and 'arm64' in asset['name']:
                url = asset['browser_download_url']
                out_path = Path(tmpdir) / 'FridaGadget.dylib'
                print(f"Downloading Frida gadget from {url}")
                urllib.request.urlretrieve(url, out_path)
                
                # Extract if it's a tarball
                if asset['name'].endswith('.tar.xz') or asset['name'].endswith('.tgz'):
                    subprocess.run(['tar', '-xf', out_path, '-C', tmpdir], check=True)
                    # Find the dylib
                    for f in Path(tmpdir).rglob('FridaGadget.dylib'):
                        return str(f)
                return str(out_path)
    except Exception as e:
        print(f"Error downloading Frida gadget: {e}")
    
    return None


def connect_frida_gadget(bundle_id: str, host: str = 'localhost', port: int = 27042) -> bool:
    """Connect to Frida gadget on device."""
    if not check_frida():
        print("Error: frida not found")
        return False
    
    # For USB device
    cmd = ['frida', '-U', '-f', bundle_id, '--no-pause']
    print(f"Connecting to {bundle_id} via Frida...")
    try:
        subprocess.run(cmd)
        return True
    except KeyboardInterrupt:
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Frida Gadget iOS Helpers')
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # patchipa
    p_patch = subparsers.add_parser('patchipa', help='Patch IPA with Frida gadget (uses objection)')
    p_patch.add_argument('ipa', help='Input IPA')
    p_patch.add_argument('-o', '--output', required=True, help='Output IPA')
    p_patch.add_argument('--identity', help='Codesign identity')
    p_patch.add_argument('--profile', help='Provisioning profile')
    p_patch.add_argument('--bundle-id', help='Bundle ID')
    
    # extract
    p_extract = subparsers.add_parser('extract', help='Extract IPA')
    p_extract.add_argument('ipa', help='Input IPA')
    p_extract.add_argument('-o', '--output', required=True, help='Output directory')
    
    # resign
    p_resign = subparsers.add_parser('resign', help='Re-sign app bundle')
    p_resign.add_argument('app', help='App bundle path')
    p_resign.add_argument('--identity', required=True, help='Codesign identity')
    p_resign.add_argument('--profile', help='Provisioning profile')
    p_resign.add_argument('--entitlements', help='Entitlements plist')
    
    # gadget-config
    p_config = subparsers.add_parser('gadget-config', help='Create FridaGadget.config')
    p_config.add_argument('app', help='App bundle path')
    p_config.add_argument('-o', '--output', help='Output config file')
    
    # connect
    p_connect = subparsers.add_parser('connect', help='Connect to Frida gadget')
    p_connect.add_argument('bundle_id', help='Bundle identifier')
    p_connect.add_argument('--host', default='localhost', help='Host')
    p_connect.add_argument('--port', type=int, default=27042, help='Port')
    
    args = parser.parse_args()
    
    if args.command == 'patchipa':
        patch_ipa_with_gadget(args.ipa, args.output, args.identity, args.profile, args.bundle_id)
    elif args.command == 'extract':
        extract_ipa(args.ipa, args.output)
    elif args.command == 'resign':
        resign_app(args.app, args.identity, args.profile, args.entitlements)
    elif args.command == 'gadget-config':
        config = default_gadget_config()
        out = args.output or os.path.join(args.app, 'FridaGadget.config')
        import json
        with open(out, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Config written to {out}")
    elif args.command == 'connect':
        connect_frida_gadget(args.bundle_id, args.host, args.port)


if __name__ == '__main__':
    main()