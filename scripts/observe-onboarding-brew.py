#!/usr/bin/env python3
"""Read only public Homebrew package metadata; never execute ZeroPW binaries.

Use a reviewed copy of this script. Output omits paths and full receipts. These
are local observations, not signed attestations. Homebrew itself is trusted.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BINARIES = ('zeropw-admin', 'zeropw-agent', 'zeropw_session', 'zeropw-demo', 'zeropw-democli')


def observe(prefix, search_path):
    keg_bin = (Path(prefix).resolve() / 'bin')
    matches = True
    for name in BINARIES:
        resolved = shutil.which(name, path=search_path)
        matches = matches and bool(resolved) and Path(resolved).resolve() == keg_bin / name
    receipt = Path(prefix) / 'INSTALL_RECEIPT.json'
    with receipt.open('rb') as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('invalid_brew_receipt')
    document = json.loads(data)
    if not isinstance(document, dict) or not isinstance(document.get('source'), dict):
        raise ValueError('invalid_brew_receipt')
    source = document['source']
    commit = source.get('tap_git_head')
    spec = source.get('spec')
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        commit = None
    if spec not in ('stable', 'head'):
        spec = None
    return {'installed_tap_commit': commit, 'installed_spec': spec,
            'binaries_resolve_to_keg': bool(matches)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approved-tap', required=True)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r'[0-9a-f]{40}', args.approved_tap):
            raise ValueError('invalid_approved_tap')
        brew = shutil.which('brew')
        if not brew:
            raise ValueError('homebrew_unavailable')
        response = subprocess.run([brew, '--prefix', 'zeropw'],
                                  env={**{k: os.environ[k] for k in ('PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR') if k in os.environ}, 'HOMEBREW_NO_AUTO_UPDATE': '1'},
                                  capture_output=True, text=True, timeout=30, check=True)
        result = observe(response.stdout.strip(), os.environ.get('PATH', ''))
        print(json.dumps(result))
        return 0 if result['installed_tap_commit'] == args.approved_tap and result['installed_spec'] == 'stable' and result['binaries_resolve_to_keg'] else 1
    except (ValueError, TypeError, OSError, RecursionError, subprocess.SubprocessError):
        print(json.dumps({'installed_tap_commit': None, 'installed_spec': None,
                          'binaries_resolve_to_keg': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
