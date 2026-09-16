#!/usr/bin/env python3
"""
launchd Job Inspection
Parse /Library/LaunchDaemons, /Library/LaunchAgents, ~/Library/LaunchAgents
Extract ProgramArguments, RunAtLoad, KeepAlive, StandardErrorPath
Identify suspicious persistence, unsigned binaries, excessive privileges
"""

import sys
import plistlib
import subprocess
import os
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime


@dataclass
class LaunchdJob:
    label: str
    plist_path: str
    domain: str  # 'system-daemon', 'system-agent', 'user-agent', 'global-daemon'
    
    # Program
    program: str = ""
    program_arguments: List[str] = field(default_factory=list)
    
    # Timing
    run_at_load: bool = False
    keep_alive: Any = False  # bool or dict
    start_interval: int = 0
    start_calendar_interval: Any = None
    throttle_interval: int = 0
    
    # I/O
    standard_in_path: str = ""
    standard_out_path: str = ""
    standard_error_path: str = ""
    
    # Environment
    environment_variables: Dict[str, str] = field(default_factory=dict)
    user_name: str = ""
    group_name: str = ""
    init_groups: bool = False
    
    # Resources
    hard_resource_limits: Dict = field(default_factory=dict)
    soft_resource_limits: Dict = field(default_factory=dict)
    nice: int = 0
    
    # Mach/XPC
    mach_services: Dict = field(default_factory=dict)
    inetd_compatibility: Dict = field(default_factory=dict)
    
    # Security
    abandon_process_group: bool = False
    enable_pressured_exit: bool = False
    enable_transactions: bool = False
    launch_only_once: bool = False
    
    # Derived
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    binary_exists: bool = False
    binary_signed: bool = False
    binary_team_id: str = ""
    binary_entitlements: Dict = field(default_factory=dict)


LAUNCHD_DIRS = {
    'system-daemon': '/System/Library/LaunchDaemons',
    'system-agent': '/System/Library/LaunchAgents',
    'global-daemon': '/Library/LaunchDaemons',
    'global-agent': '/Library/LaunchAgents',
    'user-agent': str(Path.home() / 'Library/LaunchAgents'),
}


SUSPICIOUS_PATTERNS = [
    # Paths
    ('/tmp/', 'Execution from temp directory'),
    ('/var/tmp/', 'Execution from temp directory'),
    ('/dev/shm/', 'Execution from shared memory'),
    ('.app/Contents/MacOS/', 'App binary (may be legitimate)'),
    ('/Users/', 'User home directory execution'),
    
    # Arguments
    ('curl', 'Downloads from internet'),
    ('wget', 'Downloads from internet'),
    ('python', 'Python script execution'),
    ('perl', 'Perl script execution'),
    ('ruby', 'Ruby script execution'),
    ('sh ', 'Shell execution'),
    ('bash', 'Bash execution'),
    ('zsh', 'Zsh execution'),
    ('osascript', 'AppleScript execution'),
    ('sqlite3', 'Database manipulation'),
    ('launchctl', 'Service manipulation'),
    ('codesign', 'Code signing manipulation'),
    ('xattr', 'Extended attribute manipulation'),
    ('spctl', 'Gatekeeper manipulation'),
    ('sqlite3', 'SQLite database access'),
    
    # KeepAlive with conditions
    ('SuccessfulExit', 'KeepAlive on success (persistence)'),
    ('Crashed', 'KeepAlive on crash (persistence)'),
    ('NetworkState', 'KeepAlive on network change'),
    
    # Mach services (potential XPC)
    ('MachServices', 'Exposes Mach service'),
]


def parse_launchd_plist(plist_path: str, domain: str) -> Optional[LaunchdJob]:
    """Parse a single launchd plist file."""
    try:
        with open(plist_path, 'rb') as f:
            plist = plistlib.load(f)
    except Exception as e:
        print(f"Error parsing {plist_path}: {e}")
        return None
    
    job = LaunchdJob(
        label=plist.get('Label', Path(plist_path).stem),
        plist_path=plist_path,
        domain=domain,
    )
    
    # Program
    job.program = plist.get('Program', '')
    job.program_arguments = plist.get('ProgramArguments', [])
    
    # Timing
    job.run_at_load = plist.get('RunAtLoad', False)
    job.keep_alive = plist.get('KeepAlive', False)
    job.start_interval = plist.get('StartInterval', 0)
    job.start_calendar_interval = plist.get('StartCalendarInterval')
    job.throttle_interval = plist.get('ThrottleInterval', 0)
    
    # I/O
    job.standard_in_path = plist.get('StandardInPath', '')
    job.standard_out_path = plist.get('StandardOutPath', '')
    job.standard_error_path = plist.get('StandardErrorPath', '')
    
    # Environment
    job.environment_variables = plist.get('EnvironmentVariables', {})
    job.user_name = plist.get('UserName', '')
    job.group_name = plist.get('GroupName', '')
    job.init_groups = plist.get('InitGroups', False)
    
    # Resources
    job.hard_resource_limits = plist.get('HardResourceLimits', {})
    job.soft_resource_limits = plist.get('SoftResourceLimits', {})
    job.nice = plist.get('Nice', 0)
    
    # Mach/XPC
    job.mach_services = plist.get('MachServices', {})
    job.inetd_compatibility = plist.get('inetdCompatibility', {})
    
    # Security
    job.abandon_process_group = plist.get('AbandonProcessGroup', False)
    job.enable_pressured_exit = plist.get('EnablePressuredExit', False)
    job.enable_transactions = plist.get('EnableTransactions', False)
    job.launch_only_once = plist.get('LaunchOnlyOnce', False)
    
    # Analyze binary
    binary = job.program or (job.program_arguments[0] if job.program_arguments else '')
    if binary:
        job.binary_exists = Path(binary).exists()
        if job.binary_exists:
            job.binary_signed, job.binary_team_id, job.binary_entitlements = check_binary_signature(binary)
    
    # Check for suspicious patterns
    analyze_suspicious(job)
    
    return job


def check_binary_signature(binary_path: str) -> tuple:
    """Check if binary is signed and get team ID."""
    try:
        # Check signature
        result = subprocess.run(
            ['codesign', '-v', binary_path],
            capture_output=True
        )
        signed = result.returncode == 0
        
        # Get team ID
        team_id = ""
        entitlements = {}
        if signed:
            result = subprocess.run(
                ['codesign', '-d', '-vvv', binary_path],
                capture_output=True, text=True
            )
            for line in result.stderr.split('\n'):
                if 'TeamIdentifier=' in line:
                    team_id = line.split('=', 1)[1].strip()
                elif 'Authority=' in line and 'Developer' in line:
                    pass
            
            # Get entitlements
            result = subprocess.run(
                ['codesign', '-d', '--entitlements', '-', binary_path],
                capture_output=True, text=True
            )
            xml_start = result.stderr.find('<?xml')
            if xml_start >= 0:
                import plistlib as pl
                entitlements = pl.loads(result.stderr[xml_start:].encode())
        
        return signed, team_id, entitlements
    except Exception:
        return False, "", {}


def analyze_suspicious(job: LaunchdJob):
    """Analyze job for suspicious indicators."""
    reasons = []
    
    # Check binary path and arguments
    all_text = ' '.join([job.program] + job.program_arguments).lower()
    
    for pattern, desc in SUSPICIOUS_PATTERNS:
        if pattern.lower() in all_text:
            reasons.append(f"{desc}: '{pattern}'")
    
    # Check for unsigned binary
    if job.binary_exists and not job.binary_signed:
        reasons.append("Unsigned binary")
    
    # Check for root user on user agent
    if job.domain == 'user-agent' and job.user_name == 'root':
        reasons.append("User agent running as root")
    
    # Check for world-writable binary
    if job.binary_exists:
        try:
            stat = Path(job.program).stat()
            if stat.st_mode & 0o022:
                reasons.append("Binary is world/group writable")
        except:
            pass
    
    # Check for excessive KeepAlive
    if job.keep_alive:
        if isinstance(job.keep_alive, dict):
            if job.keep_alive.get('SuccessfulExit') or job.keep_alive.get('Crashed'):
                reasons.append("KeepAlive on exit/crash (persistence)")
        elif job.keep_alive is True:
            reasons.append("KeepAlive always (persistent)")
    
    # Check for MachServices (XPC exposure)
    if job.mach_services:
        for name, config in job.mach_services.items():
            if isinstance(config, dict) and config.get('IsAgent', False):
                reasons.append(f"Exposes Mach service as agent: {name}")
            else:
                reasons.append(f"Exposes Mach service: {name}")
    
    # Check for suspicious environment variables
    for key, val in job.environment_variables.items():
        if any(k in key.upper() for k in ['PATH', 'LD_', 'DYLD_', 'HOME', 'USER']):
            reasons.append(f"Sensitive env var: {key}={val}")
    
    # Check for root daemon with network access
    if job.domain in ('system-daemon', 'global-daemon') and job.inetd_compatibility:
        reasons.append("Daemon with inetd compatibility (network listener)")
    
    job.is_suspicious = len(reasons) > 0
    job.suspicion_reasons = reasons


def enumerate_launchd_jobs(domains: List[str] = None) -> List[LaunchdJob]:
    """Enumerate all launchd jobs in specified domains."""
    if domains is None:
        domains = list(LAUNCHD_DIRS.keys())
    
    jobs = []
    for domain in domains:
        dir_path = LAUNCHD_DIRS.get(domain)
        if not dir_path:
            continue
        
        p = Path(dir_path)
        if not p.exists():
            continue
        
        for plist_file in p.glob('*.plist'):
            job = parse_launchd_plist(str(plist_file), domain)
            if job:
                jobs.append(job)
    
    return jobs


def get_running_launchd_jobs() -> Dict[str, dict]:
    """Get currently running launchd jobs via launchctl list."""
    running = {}
    try:
        result = subprocess.run(['launchctl', 'list'], capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split('\t')
            if len(parts) >= 3:
                pid, status, name = parts
                running[name] = {
                    'pid': pid if pid != '-' else None,
                    'exit_status': status if status != '-' else None,
                    'label': name
                }
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return running


def print_job(job: LaunchdJob, verbose: bool = False):
    """Print job details."""
    status = "⚠️  SUSPICIOUS" if job.is_suspicious else "✓"
    print(f"\n{status} {job.label} ({job.domain})")
    print(f"  Plist: {job.plist_path}")
    print(f"  Program: {job.program}")
    if job.program_arguments:
        print(f"  Args: {job.program_arguments}")
    print(f"  RunAtLoad: {job.run_at_load}")
    print(f"  KeepAlive: {job.keep_alive}")
    if job.start_interval:
        print(f"  StartInterval: {job.start_interval}s")
    if job.start_calendar_interval:
        print(f"  StartCalendarInterval: {job.start_calendar_interval}")
    if job.mach_services:
        print(f"  MachServices: {list(job.mach_services.keys())}")
    if job.environment_variables:
        print(f"  Env: {job.environment_variables}")
    if job.user_name:
        print(f"  User: {job.user_name}")
    if job.binary_exists:
        print(f"  Binary: exists, signed={job.binary_signed}, team={job.binary_team_id}")
    else:
        print(f"  Binary: NOT FOUND")
    
    if job.is_suspicious:
        print(f"  Reasons:")
        for r in job.suspicion_reasons:
            print(f"    - {r}")
    
    if verbose and job.binary_entitlements:
        print(f"  Entitlements:")
        for k, v in job.binary_entitlements.items():
            print(f"    {k}: {v}")


def generate_persistence_report(jobs: List[LaunchdJob], output_path: str):
    """Generate persistence analysis report."""
    report = {
        'generated': datetime.now().isoformat(),
        'total_jobs': len(jobs),
        'suspicious_jobs': len([j for j in jobs if j.is_suspicious]),
        'by_domain': {},
        'jobs': []
    }
    
    for job in jobs:
        domain = job.domain
        if domain not in report['by_domain']:
            report['by_domain'][domain] = {'total': 0, 'suspicious': 0}
        report['by_domain'][domain]['total'] += 1
        if job.is_suspicious:
            report['by_domain'][domain]['suspicious'] += 1
        
        job_data = {
            'label': job.label,
            'domain': job.domain,
            'plist_path': job.plist_path,
            'program': job.program,
            'program_arguments': job.program_arguments,
            'run_at_load': job.run_at_load,
            'keep_alive': job.keep_alive,
            'start_interval': job.start_interval,
            'mach_services': list(job.mach_services.keys()),
            'user_name': job.user_name,
            'binary_exists': job.binary_exists,
            'binary_signed': job.binary_signed,
            'binary_team_id': job.binary_team_id,
            'is_suspicious': job.is_suspicious,
            'suspicion_reasons': job.suspicion_reasons,
        }
        report['jobs'].append(job_data)
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report written to {output_path}")


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description='launchd Job Inspection')
    parser.add_argument('--domain', choices=list(LAUNCHD_DIRS.keys()) + ['all'], 
                       default='all', help='Domain to inspect')
    parser.add_argument('--plist', help='Specific plist file to inspect')
    parser.add_argument('--audit', action='store_true', help='Show only suspicious jobs')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', help='Output JSON report')
    parser.add_argument('--running', action='store_true', help='Show running jobs')
    
    args = parser.parse_args()
    
    if args.plist:
        # Determine domain from path
        domain = 'custom'
        for d, p in LAUNCHD_DIRS.items():
            if args.plist.startswith(p):
                domain = d
                break
        job = parse_launchd_plist(args.plist, domain)
        if job:
            print_job(job, args.verbose)
        return
    
    domains = None if args.domain == 'all' else [args.domain]
    jobs = enumerate_launchd_jobs(domains)
    
    print(f"=== launchd Job Inspection ===")
    print(f"Total jobs: {len(jobs)}")
    
    running = get_running_launchd_jobs()
    if running:
        print(f"Running jobs: {len(running)}")
    
    if args.running:
        print("\n--- Running Jobs ---")
        for name, info in running.items():
            print(f"  {name}: PID={info['pid']}, Status={info['exit_status']}")
        return
    
    # Filter
    if args.audit:
        jobs = [j for j in jobs if j.is_suspicious]
        print(f"Suspicious jobs: {len(jobs)}")
    
    for job in jobs:
        print_job(job, args.verbose)
    
    if args.output:
        generate_persistence_report(jobs, args.output)


if __name__ == '__main__':
    main()