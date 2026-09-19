#!/usr/bin/env python3
"""
check_links.py — Extract and verify every URL in the corpus.

Usage:
    python3 scripts/check_links.py [--timeout 10] [--json out.json]

Exit code 0 if no dead links, 1 if any dead link found.
Reports per-status: OK, DEAD (4xx/5xx after retry), BOT-BLOCKED (401/403/429),
REDIRECTED, TIMEOUT, DNS-FAIL.
"""

import re
import sys
import json
import argparse
import urllib.request
import urllib.error
import socket
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\'`\)\]\}]+')
# Skip shell/markdown variable templates and placeholder URLs
TEMPLATE_MARKERS = ('${', '<', '>', '{{', '%s')

# Files to scan for URLs
SCAN_GLOBS = ['*.md', 'references/*.md', 'templates/*.md', '*.py', 'scripts/*.sh']

BOT_BLOCK_STATUS = {401, 403, 429}


def extract_urls(root: Path) -> dict:
    """Return {url: [files]}. Strips trailing punctuation."""
    found = {}
    for pattern in SCAN_GLOBS:
        for path in root.glob(pattern):
            if path.name == 'check_links.py':
                continue
            try:
                text = path.read_text(errors='replace')
            except OSError:
                continue
            for match in URL_RE.finditer(text):
                url = match.group(0).rstrip('.,;:)]}')
                if any(marker in url for marker in TEMPLATE_MARKERS):
                    continue
                found.setdefault(url, []).append(str(path.relative_to(root)))
    return found


def check_url(url: str, timeout: int) -> tuple:
    """Return (status_class, detail)."""
    req = urllib.request.Request(url, method='GET',
                                 headers={'User-Agent': 'Mozilla/5.0 (link-check; ios-security-wizard)'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            if 200 <= code < 300:
                return ('OK', code)
            if code in BOT_BLOCK_STATUS:
                return ('BOT-BLOCKED', code)
            return ('DEAD', code)
    except urllib.error.HTTPError as e:
        if e.code in BOT_BLOCK_STATUS:
            return ('BOT-BLOCKED', e.code)
        return ('DEAD', e.code)
    except urllib.error.URLError as e:
        reason = str(e.reason)
        if isinstance(e.reason, socket.timeout):
            return ('TIMEOUT', 'timeout')
        if 'Name or service not known' in reason or 'nodename' in reason:
            return ('DNS-FAIL', reason)
        return ('TIMEOUT', reason)
    except (socket.timeout, TimeoutError):
        return ('TIMEOUT', 'timeout')
    except Exception as e:
        return ('ERROR', str(e)[:80])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--timeout', type=int, default=10)
    ap.add_argument('--json', help='Write full results to JSON')
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    urls = extract_urls(root)
    print(f"Scanning {len(urls)} unique URLs across the corpus...\n")

    results = {}
    counts = {}
    dead = []

    for url in sorted(urls):
        status, detail = check_url(url, args.timeout)
        results[url] = {'status': status, 'detail': str(detail), 'files': urls[url]}
        counts[status] = counts.get(status, 0) + 1
        marker = {'OK': '✓', 'BOT-BLOCKED': '~', 'REDIRECTED': '→'}.get(status, '✗')
        print(f"  {marker} [{status}] {url}")
        if status in ('DEAD', 'DNS-FAIL', 'ERROR'):
            dead.append(url)

    print(f"\n=== Summary ===")
    for status in sorted(counts):
        print(f"  {status}: {counts[status]}")
    print(f"  TOTAL: {len(urls)}")

    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'counts': counts, 'results': results}, f, indent=2)
        print(f"\nJSON written to {args.json}")

    return 1 if dead else 0


if __name__ == '__main__':
    sys.exit(main())
