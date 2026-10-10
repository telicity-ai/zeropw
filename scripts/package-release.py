#!/usr/bin/env python3
"""Produce a flat, checksummed binary archive; never initialize product state."""
import argparse
import hashlib
import pathlib
import re
import tarfile

BINS = ('zeropw-admin', 'zeropw-agent', 'zeropw_session', 'zeropw-demo', 'zeropw-democli')
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', required=True)
    p.add_argument('--target', required=True, choices=TARGETS)
    p.add_argument('--bin-dir', required=True, type=pathlib.Path)
    p.add_argument('--out-dir', required=True, type=pathlib.Path)
    p.add_argument('--third-party-licenses', required=True, type=pathlib.Path)
    args = p.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.version):
        p.error('version must be vMAJOR.MINOR.PATCH')
    root = pathlib.Path(__file__).resolve().parents[1]
    files = [(args.bin_dir / name, name) for name in BINS]
    files += [(root / name, name) for name in ('README.md', 'LICENSE')]
    files.append((args.third_party_licenses, 'THIRD_PARTY_LICENSES.md'))
    for path, _ in files:
        if not path.is_file() or path.is_symlink():
            p.error(f'missing regular package file: {path}')
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f'zeropw-{args.version}-{args.target}.tar.gz'
    with tarfile.open(out, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for path, name in files:
            info = archive.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            info.mode = 0o755 if name in BINS else 0o644
            with path.open('rb') as source:
                archive.addfile(info, source)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_suffix(out.suffix + '.sha256').write_text(f'{digest}  {out.name}\n')
    print(out)

if __name__ == '__main__':
    main()
