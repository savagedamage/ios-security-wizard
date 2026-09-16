#!/usr/bin/env python3
"""
XPC Service Enumeration
Enumerate XPC services from launchd, app bundles, system directories.
Parse Info.plist XPC service definitions, launchd plists.
Generate Frida/Objection probe scripts per entry point.
"""

import sys
import plistlib
import subprocess
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path


@dataclass
class XPCService:
    name: str
    type: str  # 'launchd', 'app-bundle', 'system'
    binary_path: str = ""
    bundle_id: str = ""
    run_as_root: bool = False
    mach_service_name: str = ""
    program_arguments: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    launchd_plist_path: str = ""
    entitlements: Dict = field(default_factory=dict)
    is_privileged_helper: bool = False
    is_sandboxed: bool = False


def enumerate_launchd_services() -> List[XPCService]:
    """Enumerate XPC services from launchd."""
    services = []
    
    # launchctl list shows running services
    try:
        result = subprocess.run(['launchctl', 'list'], capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            parts = line.split('\t')
            if len(parts) >= 3:
                pid, status, name = parts[0], parts[1], parts[2]
                if name.startswith('com.') and ('xpc' in name.lower() or 'helper' in name.lower()):
                    svc = XPCService(
                        name=name,
                        type='launchd',
                        mach_service_name=name,
                        run_as_root=pid != '-' and int(pid) > 0
                    )
                    services.append(svc)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Check launchd plist directories
    launchd_dirs = [
        '/System/Library/LaunchDaemons',
        '/System/Library/LaunchAgents',
        '/Library/LaunchDaemons',
        '/Library/LaunchAgents',
        Path.home() / 'Library/LaunchAgents',
    ]
    
    for dir_path in launchd_dirs:
        p = Path(dir_path)
        if not p.exists():
            continue
        for plist_file in p.glob('*.plist'):
            try:
                with open(plist_file, 'rb') as f:
                    plist = plistlib.load(f)
                
                # Check if it's an XPC service
                label = plist.get('Label', '')
                program = plist.get('Program') or (plist.get('ProgramArguments', [None])[0])
                mach_services = plist.get('MachServices', {})
                
                if mach_services or (program and 'xpc' in str(program).lower()):
                    for mach_name, mach_props in mach_services.items():
                        if isinstance(mach_props, dict):
                            svc = XPCService(
                                name=label,
                                type='launchd',
                                binary_path=str(program) if program else '',
                                mach_service_name=mach_name,
                                run_as_root='LaunchDaemons' in str(dir_path),
                                launchd_plist_path=str(plist_file),
                                program_arguments=plist.get('ProgramArguments', []),
                                environment_variables=plist.get('EnvironmentVariables', {}),
                            )
                            svc.is_privileged_helper = svc.run_as_root
                            services.append(svc)
            except Exception:
                continue
    
    return services


def enumerate_app_bundle_xpc(app_path: str) -> List[XPCService]:
    """Enumerate XPC services defined in an app bundle."""
    services = []
    app = Path(app_path)
    
    if not app.exists() or not app.is_dir():
        return services
    
    # Check Info.plist for XPC services
    info_plist = app / 'Info.plist'
    if info_plist.exists():
        try:
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
            
            # NSExtension with XPC
            extensions = plist.get('NSExtension', {})
            if extensions:
                # This is for app extensions, not XPC services directly
                pass
            
            # XPCServices key (custom, used by some apps)
            xpc_services = plist.get('XPCServices', {})
            if isinstance(xpc_services, dict):
                for name, config in xpc_services.items():
                    if isinstance(config, dict):
                        svc = XPCService(
                            name=name,
                            type='app-bundle',
                            bundle_id=plist.get('CFBundleIdentifier', ''),
                            binary_path=config.get('Executable', ''),
                            mach_service_name=config.get('MachServiceName', ''),
                            program_arguments=config.get('ProgramArguments', []),
                        )
                        services.append(svc)
        except Exception:
            pass
    
    # Check for embedded XPC services in Contents/XPCServices
    xpc_dir = app / 'Contents' / 'XPCServices'
    if xpc_dir.exists():
        for xpc_service in xpc_dir.glob('*.xpc'):
            if xpc_service.is_dir():
                xpc_plist = xpc_service / 'Contents' / 'Info.plist'
                if xpc_plist.exists():
                    try:
                        with open(xpc_plist, 'rb') as f:
                            plist = plistlib.load(f)
                        svc = XPCService(
                            name=xpc_service.name.replace('.xpc', ''),
                            type='app-bundle',
                            bundle_id=plist.get('CFBundleIdentifier', ''),
                            binary_path=str(xpc_service / 'Contents' / 'MacOS' / plist.get('CFBundleExecutable', '')),
                            mach_service_name=plist.get('MachServiceName', ''),
                            program_arguments=[plist.get('CFBundleExecutable', '')],
                            is_sandboxed=True,
                        )
                        services.append(svc)
                    except Exception:
                        continue
    
    # Check for LaunchServices in Contents/Library/LaunchServices
    ls_dir = app / 'Contents' / 'Library' / 'LaunchServices'
    if ls_dir.exists():
        for plist_file in ls_dir.glob('*.plist'):
            try:
                with open(plist_file, 'rb') as f:
                    plist = plistlib.load(f)
                # Parse launch service
            except Exception:
                continue
    
    return services


def enumerate_system_xpc() -> List[XPCService]:
    """Enumerate system XPC services."""
    services = []
    
    # Known system XPC service locations
    system_dirs = [
        '/System/Library/XPCServices',
        '/System/Library/LaunchDaemons',
        '/System/Library/LaunchAgents',
        '/usr/libexec',
    ]
    
    for dir_path in system_dirs:
        p = Path(dir_path)
        if not p.exists():
            continue
        
        if dir_path.endswith('XPCServices'):
            for xpc_service in p.glob('*.xpc'):
                if xpc_service.is_dir():
                    xpc_plist = xpc_service / 'Contents' / 'Info.plist'
                    if xpc_plist.exists():
                        try:
                            with open(xpc_plist, 'rb') as f:
                                plist = plistlib.load(f)
                            svc = XPCService(
                                name=xpc_service.name.replace('.xpc', ''),
                                type='system',
                                bundle_id=plist.get('CFBundleIdentifier', ''),
                                binary_path=str(xpc_service / 'Contents' / 'MacOS' / plist.get('CFBundleExecutable', '')),
                                mach_service_name=plist.get('MachServiceName', ''),
                                run_as_root=True,
                                is_privileged_helper=True,
                            )
                            services.append(svc)
                        except Exception:
                            continue
    
    return services


def get_service_entitlements(binary_path: str) -> Dict:
    """Get entitlements for a service binary."""
    try:
        result = subprocess.run(
            ['codesign', '-d', '--entitlements', '-', binary_path],
            capture_output=True, text=True, check=True
        )
        xml_start = result.stderr.find('<?xml')
        if xml_start >= 0:
            return plistlib.loads(result.stderr[xml_start:].encode())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return {}


def audit_xpc_service(svc: XPCService) -> Dict:
    """Audit an XPC service for security issues."""
    issues = []
    
    # Check if running as root
    if svc.run_as_root:
        issues.append(('HIGH', 'Runs as root (privileged helper)'))
    
    # Check entitlements
    if svc.binary_path:
        ents = get_service_entitlements(svc.binary_path)
        if ents:
            svc.entitlements = ents
            # Check for dangerous entitlements
            dangerous = [
                'com.apple.security.cs.disable-library-validation',
                'com.apple.security.cs.allow-unsigned-executable-memory',
                'com.apple.security.cs.allow-dyld-environment-variables',
                'com.apple.security.get-task-allow',
            ]
            for d in dangerous:
                if ents.get(d) is True:
                    issues.append(('HIGH', f'Dangerous entitlement: {d}'))
    
    # Check for sandbox
    if not svc.is_sandboxed and svc.type != 'system':
        issues.append(('MEDIUM', 'Not sandboxed'))
    
    # Check binary permissions
    if svc.binary_path:
        p = Path(svc.binary_path)
        if p.exists():
            stat = p.stat()
            if stat.st_mode & 0o022:  # world/group writable
                issues.append(('HIGH', 'Binary is world/group writable'))
            if stat.st_uid == 0:
                issues.append(('HIGH', 'Binary owned by root'))
    
    return {
        'service': svc.name,
        'type': svc.type,
        'issues': issues,
        'risk_level': max([i[0] for i in issues], default='LOW') if issues else 'LOW'
    }


def generate_xpc_probe_script(service: XPCService, output_path: str) -> bool:
    """Generate Frida/Objection probe script for an XPC service."""
    script = f"""// XPC Service Probe: {service.name}
// Target: {service.mach_service_name}
// Bundle: {service.bundle_id}
// Binary: {service.binary_path}

const XPC_SERVICE = "{service.mach_service_name}";

function connectXPC() {{
    const xpc_connection_create_mach_service = Module.findExportByName(null, 'xpc_connection_create_mach_service');
    if (!xpc_connection_create_mach_service) {{
        console.log('xpc_connection_create_mach_service not found');
        return;
    }}
    
    const conn = new NativeFunction(xpc_connection_create_mach_service, 'pointer', ['pointer', 'pointer', 'int']);
    const service_name = Memory.allocUtf8String(XPC_SERVICE);
    const connection = conn(service_name, NULL, 0);
    
    if (connection.isNull()) {{
        console.log('Failed to create XPC connection');
        return;
    }}
    
    console.log('XPC connection created:', connection);
    
    // Set event handler
    const xpc_connection_set_event_handler = Module.findExportByName(null, 'xpc_connection_set_event_handler');
    if (xpc_connection_set_event_handler) {{
        const handler = new NativeCallback(function(event) {{
            console.log('XPC event received:', event);
            // Inspect event
            const xpc_get_type = Module.findExportByName(null, 'xpc_get_type');
            if (xpc_get_type) {{
                const type_fn = new NativeFunction(xpc_get_type, 'pointer', ['pointer']);
                const type = type_fn(event);
                console.log('Event type:', type.readUtf8String());
            }}
        }}, 'void', ['pointer']);
        
        const set_handler = new NativeFunction(xpc_connection_set_event_handler, 'void', ['pointer', 'pointer']);
        set_handler(connection, handler);
    }}
    
    // Resume connection
    const xpc_connection_resume = Module.findExportByName(null, 'xpc_connection_resume');
    if (xpc_connection_resume) {{
        const resume = new NativeFunction(xpc_connection_resume, 'void', ['pointer']);
        resume(connection);
    }}
    
    // Send test message
    const xpc_dictionary_create = Module.findExportByName(null, 'xpc_dictionary_create');
    const xpc_dictionary_set_string = Module.findExportByName(null, 'xpc_dictionary_set_string');
    const xpc_connection_send_message = Module.findExportByName(null, 'xpc_connection_send_message');
    
    if (xpc_dictionary_create && xpc_dictionary_set_string && xpc_connection_send_message) {{
        const dict_create = new NativeFunction(xpc_dictionary_create, 'pointer', ['pointer', 'pointer', 'int']);
        const dict_set = new NativeFunction(xpc_dictionary_set_string, 'void', ['pointer', 'pointer', 'pointer']);
        const send = new NativeFunction(xpc_connection_send_message, 'void', ['pointer', 'pointer']);
        
        const msg = dict_create(NULL, NULL, 0);
        const key = Memory.allocUtf8String('test');
        const val = Memory.allocUtf8String('probe');
        dict_set(msg, key, val);
        send(connection, msg);
        console.log('Test message sent');
    }}
    
    return connection;
}}

// Auto-run
setImmediate(connectXPC);
"""
    
    try:
        with open(output_path, 'w') as f:
            f.write(script)
        return True
    except Exception as e:
        print(f"Error writing probe: {e}")
        return False


def generate_objection_xpc_probe(service: XPCService) -> str:
    """Generate Objection command for XPC exploration."""
    return f"""# Objection XPC Exploration for {service.name}
# Run: objection -g {service.bundle_id} explore

# List XPC connections
ios xpc connection list

# Connect to specific service
ios xpc connection create {service.mach_service_name}

# Send dictionary message
ios xpc connection send {service.mach_service_name} --dict '{{"test": "probe"}}'

# Monitor replies
ios xpc connection monitor {service.mach_service_name}
"""


def main():
    import argparse
    parser = argparse.ArgumentParser(description='XPC Service Enumeration')
    parser.add_argument('target', nargs='?', help='Target: app bundle path, or "system"')
    parser.add_argument('--launchd', action='store_true', help='Enumerate launchd services')
    parser.add_argument('--system', action='store_true', help='Enumerate system XPC services')
    parser.add_argument('--audit', action='store_true', help='Audit services for security issues')
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument('--generate-probes', help='Generate probe scripts to directory')
    
    args = parser.parse_args()
    
    all_services = []
    
    if args.target and args.target != 'system':
        # App bundle
        services = enumerate_app_bundle_xpc(args.target)
        all_services.extend(services)
        print(f"Found {len(services)} XPC services in app bundle")
    elif args.launchd or args.target == 'launchd':
        services = enumerate_launchd_services()
        all_services.extend(services)
        print(f"Found {len(services)} launchd XPC services")
    elif args.system or args.target == 'system':
        services = enumerate_system_xpc()
        all_services.extend(services)
        print(f"Found {len(services)} system XPC services")
    else:
        # All
        all_services.extend(enumerate_launchd_services())
        all_services.extend(enumerate_system_xpc())
        print(f"Total services: {len(all_services)}")
    
    # Audit
    if args.audit:
        print("\n--- Security Audit ---")
        for svc in all_services:
            audit = audit_xpc_service(svc)
            if audit['issues']:
                print(f"\n{svc.name} ({audit['risk_level']}):")
                for level, issue in audit['issues']:
                    print(f"  [{level}] {issue}")
    
    # Generate probes
    if args.generate_probes:
        out_dir = Path(args.generate_probes)
        out_dir.mkdir(parents=True, exist_ok=True)
        for svc in all_services:
            probe_path = out_dir / f"probe_{svc.name.replace('.', '_')}.js"
            generate_xpc_probe_script(svc, str(probe_path))
            print(f"Generated: {probe_path}")
    
    # Output JSON
    if args.output:
        data = []
        for svc in all_services:
            data.append({
                'name': svc.name,
                'type': svc.type,
                'binary_path': svc.binary_path,
                'bundle_id': svc.bundle_id,
                'mach_service_name': svc.mach_service_name,
                'run_as_root': svc.run_as_root,
                'is_privileged_helper': svc.is_privileged_helper,
                'is_sandboxed': svc.is_sandboxed,
                'program_arguments': svc.program_arguments,
            })
        with open(args.output, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Output written to {args.output}")
    
    # Print summary
    for svc in all_services:
        print(f"\n{svc.name} ({svc.type})")
        print(f"  Mach Service: {svc.mach_service_name}")
        print(f"  Bundle ID: {svc.bundle_id}")
        print(f"  Binary: {svc.binary_path}")
        print(f"  Root: {svc.run_as_root}, Privileged: {svc.is_privileged_helper}, Sandboxed: {svc.is_sandboxed}")


if __name__ == '__main__':
    main()