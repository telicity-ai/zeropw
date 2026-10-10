#!/usr/bin/env python3
"""Build native binary archives with a pinned, statically linked OpenSSL SDK."""
import argparse
import hashlib
import os
import re
import pathlib
import platform
import subprocess
import tarfile

OPENSSL_VERSION = '3.5.9'
OPENSSL_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
OPENSSL_URL = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz'
HOSTS = {('Darwin', 'arm64'): ('aarch64-apple-darwin', 'darwin64-arm64-cc'),
         ('Darwin', 'x86_64'): ('x86_64-apple-darwin', 'darwin64-x86_64-cc'),
         ('Linux', 'aarch64'): ('aarch64-unknown-linux-gnu', 'linux-aarch64'),
         ('Linux', 'x86_64'): ('x86_64-unknown-linux-gnu', 'linux-x86_64')}


def run(command, cwd, environment):
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--out-dir', required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.version):
        parser.error('version must be vMAJOR.MINOR.PATCH')
    host = HOSTS.get((platform.system(), platform.machine()))
    if not host or args.target != host[0]:
        parser.error('use a native builder matching the requested target')
    root = pathlib.Path(__file__).resolve().parents[1]
    output = args.out_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = output / 'openssl-build'
    work.mkdir(exist_ok=True)
    archive = work / ('openssl-' + OPENSSL_VERSION + '.tar.gz')
    environment = dict(os.environ)
    if not archive.exists():
        partial = archive.with_suffix('.partial')
        run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
             '--proto-redir', '=https', '--connect-timeout', '15', '--max-time', '300',
             '--max-filesize', '70000000', OPENSSL_URL, '-o', str(partial)], root, environment)
        partial.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != OPENSSL_SHA256:
        raise SystemExit('OpenSSL source checksum mismatch')
    source = work / ('openssl-' + OPENSSL_VERSION)
    sdk = work / 'sdk'
    # Always rebuild from the authenticated archive; an existing mutable SDK is not evidence.
    import shutil
    shutil.rmtree(source, ignore_errors=True)
    shutil.rmtree(sdk, ignore_errors=True)
    with tarfile.open(archive) as contents:
        for member in contents.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != source.name:
                raise SystemExit('unexpected OpenSSL source path')
            if not member.isfile() and not member.isdir():
                raise SystemExit('OpenSSL source archive contains a link or special entry')
            member.mode &= 0o777
        contents.extractall(work)
    run(['perl', 'Configure', host[1], 'no-shared', 'no-module', 'no-tests',
         '--prefix=' + str(sdk), '--openssldir=/etc/ssl', '--libdir=lib'], source, environment)
    run(['make', '-j' + str(min(os.cpu_count() or 1, 8))], source, environment)
    run(['make', 'install_sw'], source, environment)
    environment.update(OPENSSL_DIR=str(sdk), OPENSSL_STATIC='1',
                       CARGO_TARGET_DIR=str(output / 'cargo-target'))
    environment.pop('OPENSSL_NO_VENDOR', None)
    run(['cargo', 'build', '--locked', '--release', '--features', 'bundled-openssl',
         '--target', args.target, '--manifest-path', str(root / 'rust/Cargo.toml'), '--bins'], root, environment)
    notices = output / 'THIRD_PARTY_LICENSES.md'
    run(['python3', str(root / 'scripts/dependency-licenses.py'), '--features', 'bundled-openssl',
         '--target', args.target, '--openssl-source', str(source), '--output', str(notices)], root, environment)
    run(['python3', str(root / 'scripts/package-release.py'), '--version', args.version,
         '--target', args.target, '--bin-dir', str(output / 'cargo-target' / args.target / 'release'),
         '--out-dir', str(output), '--third-party-licenses', str(notices)], root, environment)


if __name__ == '__main__':
    main()
