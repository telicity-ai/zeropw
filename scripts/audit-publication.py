#!/usr/bin/env python3
"""Scan tracked source without printing matched values. Findings need review."""
import argparse
import json
import pathlib
import re
import subprocess

RULES = {
    'personal_absolute_path': re.compile(rb'/(?:Users|home)/[A-Za-z0-9_.-]+/'),
    'github_token_shape': re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'aws_access_key_shape': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'private_key_marker': re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----'),
}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--history', action='store_true', help='scan every reachable Git blob once')
    args = p.parse_args()
    root = pathlib.Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
    findings = []
    scanned = 0
    if args.history:
        entries = subprocess.check_output(['git', 'rev-list', '--objects', '--all'], cwd=root).splitlines()
        for entry in entries:
            parts = entry.split(b' ', 1)
            if len(parts) != 2:
                continue
            oid, name = parts
            if subprocess.check_output(['git', 'cat-file', '-t', oid.decode()], cwd=root).strip() != b'blob':
                continue
            data = subprocess.check_output(['git', 'cat-file', 'blob', oid.decode()], cwd=root)
            scanned += 1
            inspect(data, name.decode('utf-8', 'replace'), findings, oid.decode())
    else:
        names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).split(b'\0')
        for name in names:
            if not name:
                continue
            path = root / name.decode('utf-8')
            if path.is_symlink() or not path.is_file():
                continue
            scanned += 1
            inspect(path.read_bytes(), name.decode('utf-8'), findings, None)
    print(json.dumps({'mode': 'history' if args.history else 'tracked_tree',
                      'files_or_blobs_scanned': scanned, 'findings': findings}, indent=2))
    # Findings are evidence, not proof that a credential is live or synthetic.
    # A clean narrow scan is not a comprehensive secret audit.
    return 1 if findings else 0

def inspect(data, name, findings, oid):
    for rule, pattern in RULES.items():
        count = len(pattern.findall(data))
        if count:
            finding = {'path': name, 'rule': rule, 'occurrences': count}
            if oid:
                finding['blob'] = oid
            findings.append(finding)

if __name__ == '__main__':
    raise SystemExit(main())
