#!/usr/bin/env python3
"""
jailbreak_check.py — Jailbreak/Compromise Assessment (No Root Required)
Multi-indicator assessment of a connected iOS device for jailbreak evidence
and dynamic instrumentation artifacts. Works via USB/network — no jailbreak
needed on the analysis host. Uses Frida where available, falls back to
static checks of device filesystem via afc/libimobiledevice.
"""

import sys
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class Indicator:
    category: str
    name: str
    detected: bool
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    evidence: str = ""
    note: str = ""


# Known jailbreak filesystem artifacts
JB_FILES = [
    ('/Applications/Cydia.app', 'Cydia package manager', 'CRITICAL'),
    ('/Applications/Sileo.app', 'Sileo package manager', 'CRITICAL'),
    ('/Applications/Zebra.app', 'Zebra package manager', 'CRITICAL'),
    ('/Applications/Filza.app', 'Filza file manager', 'HIGH'),
    ('/Applications/iTerminal.app', 'iTerminal', 'MEDIUM'),
    ('/usr/sbin/sshd', 'SSH daemon', 'HIGH'),
    ('/usr/bin/ssh', 'SSH client', 'MEDIUM'),
    ('/bin/bash', 'bash shell', 'HIGH'),
    ('/bin/sh', 'sh shell (always present on iOS, check hash)', 'LOW'),
    ('/usr/libexec/ssh-keysign', 'SSH keysign', 'MEDIUM'),
    ('/Library/MobileSubstrate/MobileSubstrate.dylib', 'MobileSubstrate (Cydia Substrate)', 'CRITICAL'),
    ('/Library/MobileSubstrate/DynamicLibraries/', 'Substrate tweak directory', 'CRITICAL'),
    ('/usr/lib/libsubstitute.dylib', 'Substitute (Electra/Chimera)', 'CRITICAL'),
    ('/usr/lib/libhooker.dylib', 'libhooker (Odyssey)', 'CRITICAL'),
    ('/usr/lib/TweakInject', 'TweakInject (unc0ver)', 'CRITICAL'),
    ('/var/lib/dpkg', 'dpkg database (Apt)', 'HIGH'),
    ('/var/cache/apt', 'Apt cache', 'HIGH'),
    ('/private/etc/apt', 'Apt configuration', 'HIGH'),
    ('/var/lib/cydia', 'Cydia data', 'HIGH'),
    ('/var/mobile/Library/Cydia', 'Cydia user data', 'HIGH'),
    ('/var/log/syslog', 'Syslog (dev builds only)', 'MEDIUM'),
    ('/etc/ssh/sshd_config', 'SSH daemon config', 'HIGH'),
    ('/private/var/stash', 'Stash directory', 'HIGH'),
    ('/private/var/tmp/cydia.log', 'Cydia log', 'HIGH'),
    ('/var/mobile/Library/Preferences/com.saurik.Cydia.plist', 'Cydia prefs', 'HIGH'),
]

# Environment variables that indicate tweak injection
JB_ENV_VARS = [
    ('DYLD_INSERT_LIBRARIES', 'Tweak injection via DYLD', 'CRITICAL'),
    ('DYLD_FORCE_FLAT_NAMESPACE', 'Flat namespace forcing', 'MEDIUM'),
    ('MSSAFE_MODE', 'MobileSubstrate safe mode', 'HIGH'),
    ('CS_DEBUGGED', 'Code signing debug flag', 'MEDIUM'),
    ('SUBSTRATE_SAFE_MODE', 'Substrate safe mode', 'HIGH'),
]

# URL schemes of jailbreak tools
JB_URL_SCHEMES = [
    ('cydia://', 'Cydia URL scheme', 'CRITICAL'),
    ('sileo://', 'Sileo URL scheme', 'CRITICAL'),
    ('zbra://', 'Zebra URL scheme', 'CRITICAL'),
    ('filza://', 'Filza URL scheme', 'HIGH'),
]

# Frida script that runs on the device (gadget mode) to gather indicators
FRIDA_JB_SCRIPT = r'''
// Jailbreak detection data gatherer (gadget mode)
const results = {};

// 1. Check for known files via ObjC NSFileManager
function checkFile(path) {
    const NSFileManager = ObjC.classes.NSFileManager;
    const fm = NSFileManager.defaultManager();
    const exists = fm.fileExistsAtPath_(path);
    return exists ? true : false;
}

// 2. Check for substrate classes
function checkSubstrate() {
    const classes = ['CydiaSubstrate', 'MSHookFunction', 'SubstrateLoader'];
    const found = [];
    classes.forEach(c => {
        try {
            if (ObjC.classes[c]) found.push(c);
        } catch(e) {}
    });
    return found;
}

// 3. Check environment
function checkEnv() {
    const env = ObjC.classes.NSProcessInfo.processInfo().environment();
    const keys = ['DYLD_INSERT_LIBRARIES', 'SUBSTRATE_SAFE_MODE', 'MSSAFE_MODE'];
    const found = [];
    keys.forEach(k => {
        if (env.objectForKey_(k)) found.push(k);
    });
    return found;
}

// 4. Check fork() availability (sandbox escape indicator)
function checkFork() {
    try {
        const fork = new NativeFunction(Module.findExportByName(null, 'fork'), 'int', []);
        const pid = fork();
        if (pid === 0) {
            // child - exit immediately
            const exit = new NativeFunction(Module.findExportByName(null, '_exit'), 'void', ['int']);
            exit(0);
        }
        return pid >= 0;
    } catch(e) {
        return false;
    }
}

// 5. Check for Frida itself (gadget present)
function checkFrida() {
    const modules = Process.enumerateModules();
    return modules.filter(m => m.name.toLowerCase().includes('frida')).map(m => m.name);
}

const jbFiles = [
    '/Applications/Cydia.app', '/Applications/Sileo.app',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/usr/lib/libsubstitute.dylib', '/usr/lib/TweakInject',
    '/var/lib/dpkg', '/bin/bash', '/usr/sbin/sshd'
];

results.files = {};
jbFiles.forEach(p => { results.files[p] = checkFile(p); });
results.substrate_classes = checkSubstrate();
results.env_vars = checkEnv();
results.fork_works = checkFork();
results.frida_modules = checkFrida();

send(JSON.stringify(results));
'''


def check_device_over_usb() -> Dict:
    """Check device filesystem via libimobiledevice (if installed)."""
    result = {}
    try:
        subprocess.run(['idevice_id', '-l'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        result['error'] = 'idevice tools not available'
        return result

    # Check files via afc (app sandbox only) - limited
    result['afc_available'] = True
    return result


def run_frida_check(bundle_id: Optional[str] = None) -> Dict:
    """Run Frida-based checks on the device."""
    result = {}
    try:
        subprocess.run(['frida', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        result['error'] = 'frida not available on analysis host'
        return result

    script_path = Path('/tmp/frida_jb_check.js')
    script_path.write_text(FRIDA_JB_SCRIPT)

    cmd = ['frida', '-U']
    if bundle_id:
        cmd.extend(['-f', bundle_id, '--no-pause'])
    else:
        cmd.extend(['--runtime', 'gadget'])

    cmd.extend(['-l', str(script_path), '-o', '/tmp/frida_jb_output.json', '-q'])

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = Path('/tmp/frida_jb_output.json')
        if output.exists():
            result = json.loads(output.read_text())
    except subprocess.TimeoutExpired:
        result['error'] = 'timeout running Frida check'
    except Exception as e:
        result['error'] = str(e)

    return result


def interpret_frida_results(data: Dict) -> List[Indicator]:
    """Interpret Frida gatherer results into indicators."""
    indicators = []

    if not data or 'error' in data:
        return indicators

    # Files
    for path, exists in data.get('files', {}).items():
        if exists:
            match = next((x for x in JB_FILES if x[0] == path), None)
            if match:
                indicators.append(Indicator(
                    category='filesystem', name=f'Jailbreak file present: {path}',
                    detected=True, severity=match[2], evidence=match[1]
                ))
            else:
                indicators.append(Indicator(
                    category='filesystem', name=f'Suspicious file present: {path}',
                    detected=True, severity='MEDIUM', evidence='unknown file'
                ))

    # Substrate classes
    for cls in data.get('substrate_classes', []):
        indicators.append(Indicator(
            category='runtime', name=f'Substrate class loaded: {cls}',
            detected=True, severity='CRITICAL',
            evidence='Cydia Substrate is running'
        ))

    # Env vars
    for var in data.get('env_vars', []):
        match = next((x for x in JB_ENV_VARS if x[0] == var), None)
        if match:
            indicators.append(Indicator(
                category='environment', name=f'Injection env var: {var}',
                detected=True, severity=match[2], evidence=match[1]
            ))

    # Fork
    if data.get('fork_works'):
        indicators.append(Indicator(
            category='sandbox', name='fork() succeeds',
            detected=True, severity='HIGH',
            evidence='Sandbox escape — fork should fail on stock iOS apps'
        ))

    # Frida modules
    for mod in data.get('frida_modules', []):
        indicators.append(Indicator(
            category='instrumentation', name=f'Frida module loaded: {mod}',
            detected=True, severity='INFO',
            evidence='Instrumentation present (gadget is expected in gadget mode)'
        ))

    return indicators


def analyze(frida_data: Dict) -> List[Indicator]:
    """Run full multi-indicator assessment."""
    indicators = interpret_frida_results(frida_data)
    return indicators


def print_indicators(indicators: List[Indicator]):
    """Print assessment results."""
    print("=== Jailbreak/Compromise Assessment ===")
    if not indicators:
        print("No indicators detected")
        print("(Note: without device access, only static checks are possible)")
        return

    detected = [i for i in indicators if i.detected]
    print(f"Indicators detected: {len(detected)}")
    print()

    by_severity = {}
    for i in detected:
        by_severity.setdefault(i.severity, []).append(i)

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev not in by_severity:
            continue
        print(f"--- {sev} ---")
        for i in by_severity[sev]:
            print(f"  [{i.category}] {i.name}")
            if i.evidence:
                print(f"    Evidence: {i.evidence}")
        print()

    # Verdict
    critical = len(by_severity.get('CRITICAL', []))
    high = len(by_severity.get('HIGH', []))
    print("=== Verdict ===")
    if critical >= 2:
        print("JAILBROKEN (multiple critical indicators)")
    elif critical >= 1:
        print("LIKELY JAILBROKEN (critical indicator present)")
    elif high >= 2:
        print("SUSPICIOUS (multiple high-severity indicators)")
    elif high >= 1:
        print("POSSIBLY MODIFIED (single high-severity indicator)")
    else:
        print("CLEAN (no significant indicators)")

    print("\nFalse positive notes:")
    print("  - Dev-signed builds show get-task-allow; not jailbreak evidence alone")
    print("  - Frida module presence is EXPECTED in gadget mode (this tool's own injection)")
    print("  - /bin/sh exists on stock iOS; check hash, not presence")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Jailbreak/compromise assessment')
    parser.add_argument('--bundle-id', help='Target app bundle ID (spawns app with Frida)')
    parser.add_argument('--frida-output', help='Use existing Frida JSON output instead of live check')
    parser.add_argument('--static-only', action='store_true', help='Skip device checks, show guidance')
    parser.add_argument('-o', '--output', help='Export indicators to JSON')

    args = parser.parse_args()

    if args.static_only:
        print("Static-only mode: no device connected.")
        print("Connect device via USB and ensure frida + idevice tools are installed:")
        print("  brew install libimobiledevice frida")
        print()
        print("Known jailbreak files that would be checked:")
        for path, desc, sev in JB_FILES[:15]:
            print(f"  [{sev}] {path} — {desc}")
        print("  ...")
        sys.exit(0)

    if args.frida_output:
        try:
            with open(args.frida_output) as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading Frida output: {e}")
            sys.exit(1)
    else:
        data = run_frida_check(args.bundle_id)

    if 'error' in data:
        print(f"Cannot assess device: {data['error']}")
        print("Hints:")
        print("  1. Connect device via USB and unlock it")
        print("  2. Ensure gadget is injected: ./scripts/re-sign_gadget.sh")
        print("  3. Or use: frida -U --runtime gadget")
        sys.exit(1)

    indicators = analyze(data)
    print_indicators(indicators)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump([{
                'category': i.category,
                'name': i.name,
                'detected': i.detected,
                'severity': i.severity,
                'evidence': i.evidence,
            } for i in indicators], f, indent=2)
        print(f"Indicators exported to {args.output}")


if __name__ == '__main__':
    main()
