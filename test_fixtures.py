#!/usr/bin/env python3
"""
Component test suite for ios-security-wizard.
Builds real Mach-O fixtures and exercises every tool end-to-end.

Run: ./ios-wizard test   or   python3 test_fixtures.py
"""

import os
import sys
import struct
import tempfile
import subprocess
import json

# Add all skill directories to path
skill_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(skill_root, 'static'))
sys.path.insert(0, os.path.join(skill_root, 'dynamic'))
sys.path.insert(0, os.path.join(skill_root, 'pentest'))
sys.path.insert(0, os.path.join(skill_root, 'test'))

from macho_parser import MachOParser, Magic, CpuType, FileType, LoadCommand
from macho_fixture import build_macho_arm64

FIXTURE_DIR = None


def setup_fixtures():
    global FIXTURE_DIR
    FIXTURE_DIR = tempfile.mkdtemp(prefix='ioswiz_test_')
    build_macho_arm64(os.path.join(FIXTURE_DIR, 'sample.macho'))
    build_macho_arm64(os.path.join(FIXTURE_DIR, 'sample_nostrings.macho'), with_strings=False)
    return FIXTURE_DIR


def test_macho_parser_enums():
    """Test enums and MachHeader dataclass."""
    print("Testing Mach-O parser constants...")
    try:
        assert Magic.MH_MAGIC_64 == 0xfeedfacf
        assert CpuType.CPU_TYPE_ARM64 == 0x0100000c
        assert FileType.MH_EXECUTE == 0x2
        assert LoadCommand.LC_SEGMENT_64 == 0x19
        assert LoadCommand.LC_CODE_SIGNATURE == 0x1d
        assert LoadCommand.LC_DYLD_CHAINED_FIXUPS == 0x34

        from macho_parser import MachHeader
        header = MachHeader(
            magic=Magic.MH_MAGIC_64,
            cputype=CpuType.CPU_TYPE_ARM64,
            cpusubtype=0,
            filetype=FileType.MH_EXECUTE,
            ncmds=10,
            sizeofcmds=1000,
            flags=0x200080
        )
        assert header.is_64bit == True
        assert header.cpu_arch == 'arm64'
        assert header.is_swapped == False
        print("✓ Parser constants PASSED")
        return True
    except Exception as e:
        print(f"✗ Parser constants FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_macho_parser_real_fixture():
    """Parse a real fixture Mach-O end-to-end."""
    print("Testing Mach-O parser on real fixture...")
    try:
        fixture = os.path.join(FIXTURE_DIR, 'sample.macho')
        parser = MachOParser(fixture)

        # Header checks
        assert parser.header is not None
        assert parser.header.is_64bit
        assert parser.header.cpu_arch == 'arm64'
        assert parser.header.filetype == FileType.MH_EXECUTE
        assert parser.header.ncmds == 11

        # Segments
        segments = parser.get_segments()
        seg_names = {s.segname for s in segments}
        assert '__TEXT' in seg_names
        assert '__DATA' in seg_names
        assert '__LINKEDIT' in seg_names
        assert '__PAGEZERO' in seg_names

        # Sections
        sections = parser.get_sections()
        sect_names = {s.sectname for s in sections}
        assert '__text' in sect_names
        assert '__cstring' in sect_names
        assert '__data' in sect_names

        # Symbols
        sym_names = {s.name for s in parser.symbols}
        assert '_main' in sym_names
        assert '__stack_chk_guard' in sym_names

        # UUID
        assert parser.get_uuid() is not None

        # Security checks
        pie = parser.check_pie_stack_canary_arc()
        assert pie['pie'] == True
        assert pie['stack_canary'] == True

        print("✓ Parser fixture test PASSED")
        return True
    except Exception as e:
        print(f"✗ Parser fixture test FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_objc_swift_on_fixture():
    """Run ObjC/Swift parser on the fixture (should not crash, may find nothing)."""
    print("Testing ObjC/Swift metadata parser...")
    try:
        from objc_swift import ObjCParser, SwiftParser
        fixture = os.path.join(FIXTURE_DIR, 'sample.macho')
        macho = MachOParser(fixture)
        objc = ObjCParser(macho)
        swift = SwiftParser(macho)
        # Fixture has no ObjC sections — the point is clean execution
        print("✓ ObjC/Swift parser PASSED (no crash on clean binary)")
        return True
    except Exception as e:
        print(f"✗ ObjC/Swift parser FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_crypto_scan_on_fixture():
    """Crypto scanner should find planted weaknesses in fixture."""
    print("Testing crypto scanner on fixture...")
    try:
        from crypto_scan import scan_binary
        fixture = os.path.join(FIXTURE_DIR, 'sample.macho')
        findings = scan_binary(fixture)

        titles = [f.title for f in findings]
        assert any('ECB' in t for t in titles), "ECB finding missing"
        assert any('AccessibleAlways' in t or 'locked' in t for t in titles), "keychain finding missing"

        # Severity ordering
        ecb = next(f for f in findings if 'ECB' in f.title)
        assert ecb.severity == 'CRITICAL'

        print(f"✓ Crypto scanner PASSED ({len(findings)} findings)")
        return True
    except Exception as e:
        print(f"✗ Crypto scanner FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_ipa_structure():
    """Test IPA structure analyzer."""
    print("Testing IPA structure analyzer...")
    try:
        from ipa_structure import BundleInfo, analyze_bundle
        # Create a minimal .app bundle
        import plistlib
        app_dir = os.path.join(FIXTURE_DIR, 'Test.app')
        os.makedirs(app_dir, exist_ok=True)
        plist = {
            'CFBundleIdentifier': 'com.test.app',
            'CFBundleExecutable': 'Test',
            'CFBundleVersion': '1',
            'CFBundleShortVersionString': '1.0',
            'MinimumOSVersion': '16.0',
            'CFBundleURLTypes': [{'CFBundleURLName': 'test', 'CFBundleURLSchemes': ['testapp']}],
            'NSAppTransportSecurity': {'NSAllowsArbitraryLoads': True},
        }
        with open(os.path.join(app_dir, 'Info.plist'), 'wb') as f:
            plistlib.dump(plist, f)

        info = analyze_bundle(app_dir)
        assert info.bundle_id == 'com.test.app'
        assert 'testapp' in info.url_schemes
        assert info.ats_config.get('NSAllowsArbitraryLoads') == True
        print("✓ IPA structure analyzer PASSED")
        return True
    except Exception as e:
        print(f"✗ IPA structure analyzer FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_jailbreak_check():
    """Test jailbreak check tool structure."""
    print("Testing jailbreak check...")
    try:
        from jailbreak_check import JB_FILES, JB_ENV_VARS, interpret_frida_results
        assert len(JB_FILES) > 10
        assert len(JB_ENV_VARS) > 3

        # Test interpretation with synthetic data
        fake = {
            'files': {'/Applications/Cydia.app': True, '/bin/bash': True},
            'substrate_classes': ['MSHookFunction'],
            'env_vars': ['DYLD_INSERT_LIBRARIES'],
            'fork_works': True,
            'frida_modules': ['FridaGadget.dylib'],
        }
        indicators = interpret_frida_results(fake)
        assert len(indicators) >= 5
        sevs = [i.severity for i in indicators]
        assert 'CRITICAL' in sevs

        print(f"✓ Jailbreak check PASSED ({len(indicators)} indicators)")
        return True
    except Exception as e:
        print(f"✗ Jailbreak check FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_report_gen():
    """Test report generator with synthetic findings."""
    print("Testing report generator...")
    try:
        from report_gen import normalize_crypto_findings, generate_report

        raw = [{
            'severity': 'CRITICAL',
            'category': 'encryption-mode',
            'title': 'ECB mode encryption',
            'evidence': 'kCCOptionECBMode',
            'offset': 0x1000,
            'section': '__cstring',
        }]
        findings = normalize_crypto_findings(raw, 'crypto_scan')
        assert findings[0].id == 'F-crypto-1'
        assert findings[0].severity == 'CRITICAL'

        out_path = os.path.join(FIXTURE_DIR, 'report.md')
        generated = generate_report([(raw, 'crypto_scan')], 'test-target', out_path)
        assert os.path.exists(out_path)
        content = open(out_path).read()
        assert 'CRITICAL' in content
        assert 'ECB' in content

        print("✓ Report generator PASSED")
        return True
    except Exception as e:
        print(f"✗ Report generator FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_entitlements_parser():
    """Test entitlements parser."""
    print("Testing entitlements parser...")
    try:
        from entitlements import analyze_entitlements, ProvisioningProfile

        profile = ProvisioningProfile(path='test', raw_data=b'')
        profile.entitlements = {
            'keychain-access-groups': ['TEAMID.*'],
            'com.apple.developer.networking.networkextension': ['packet-tunnel'],
            'com.apple.security.cs.runtime': True,
            'com.apple.security.cs.allow-jit': True,
        }
        analyze_entitlements(profile)
        assert profile.has_wildcard_keychain == True
        assert any('Wildcard' in x for x in profile.over_privileged)
        assert any('JIT' in x for x in profile.missing_restrictions)
        print("✓ Entitlements parser PASSED")
        return True
    except Exception as e:
        print(f"✗ Entitlements parser FAILED: {e}")
        import traceback; traceback.print_exc()
        return False


def test_dyld_cache_parser():
    """Test dyld cache parser structure."""
    print("Testing dyld cache parser...")
    try:
        from dyld_cache import parse_dyld_cache_header, find_dyld_cache_paths
        paths = find_dyld_cache_paths()
        print(f"  Found {len(paths)} dyld cache paths (expected 0 on Linux)")
        print("✓ Dyld cache parser structure OK")
        return True
    except Exception as e:
        print(f"✗ Dyld cache parser FAILED: {e}")
        return False


def test_hardened_runtime():
    """Test hardened runtime checker."""
    print("Testing hardened runtime checker...")
    try:
        from hardened_runtime import audit_hardened_runtime, HardenedRuntimeFlags
        flags = audit_hardened_runtime('/nonexistent')
        assert isinstance(flags, HardenedRuntimeFlags)
        assert flags.runtime == False
        print("✓ Hardened runtime checker structure OK")
        return True
    except Exception as e:
        print(f"✗ Hardened runtime checker FAILED: {e}")
        return False


def test_ipa_diff():
    """Test IPA diff structure."""
    print("Testing IPA diff...")
    try:
        from ipa_diff import DiffFinding, Severity as DiffSeverity, BinaryInfo
        finding = DiffFinding(
            category='test', severity=DiffSeverity.HIGH,
            title='Test finding', description='Test description'
        )
        assert finding.severity == DiffSeverity.HIGH
        print("✓ IPA diff structure OK")
        return True
    except Exception as e:
        print(f"✗ IPA diff FAILED: {e}")
        return False


def test_probe_plan():
    """Test probe plan generator."""
    print("Testing probe plan...")
    try:
        from probe_plan import ProbeTarget, analyze_attack_surface
        target = ProbeTarget(
            target_type='url-scheme', identifier='myapp',
            details={'name': 'MyApp'}, priority='HIGH'
        )
        assert target.priority == 'HIGH'
        print("✓ Probe plan structure OK")
        return True
    except Exception as e:
        print(f"✗ Probe plan FAILED: {e}")
        return False


def test_device_baseline():
    """Test device baseline."""
    print("Testing device baseline...")
    try:
        from device_baseline import DeviceBaseline, capture_sysctls
        baseline = DeviceBaseline(timestamp='2024-01-01T00:00:00')
        assert baseline.timestamp == '2024-01-01T00:00:00'
        sysctls = capture_sysctls()
        print(f"  Captured {len(sysctls)} sysctls")
        print("✓ Device baseline structure OK")
        return True
    except Exception as e:
        print(f"✗ Device baseline FAILED: {e}")
        return False


def test_xpc_enum():
    """Test XPC enumeration."""
    print("Testing XPC enumeration...")
    try:
        from xpc_enum import enumerate_launchd_services, enumerate_system_xpc
        launchd = enumerate_launchd_services()
        system = enumerate_system_xpc()
        print(f"  Launchd services: {len(launchd)}, System XPC: {len(system)}")
        print("✓ XPC enumeration structure OK")
        return True
    except Exception as e:
        print(f"✗ XPC enumeration FAILED: {e}")
        return False


def test_launchd_inspect():
    """Test launchd inspection."""
    print("Testing launchd inspection...")
    try:
        from launchd_inspect import enumerate_launchd_jobs, LAUNCHD_DIRS
        jobs = enumerate_launchd_jobs(['user-agent'])
        print(f"  Found {len(jobs)} user agent jobs")
        print("✓ Launchd inspection structure OK")
        return True
    except Exception as e:
        print(f"✗ Launchd inspection FAILED: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("iOS Security Wizard - Component Tests")
    print("=" * 60)

    setup_fixtures()
    print(f"Fixtures at: {FIXTURE_DIR}")
    print()

    tests = [
        test_macho_parser_enums,
        test_macho_parser_real_fixture,
        test_objc_swift_on_fixture,
        test_crypto_scan_on_fixture,
        test_ipa_structure,
        test_jailbreak_check,
        test_report_gen,
        test_entitlements_parser,
        test_dyld_cache_parser,
        test_hardened_runtime,
        test_ipa_diff,
        test_probe_plan,
        test_device_baseline,
        test_xpc_enum,
        test_launchd_inspect,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__} FAILED with exception: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
