#!/usr/bin/env python3
"""Build native binary archives with a pinned, statically linked OpenSSL SDK.

With --bin NAME (repeatable) it builds only the named release binaries the same way, checks
their linkage, collects the notices and copies them to OUT_DIR/bin without packaging an
archive (the desktop app ships zeropw-admin, zeropw_session and zeropw-agent this way).
In archive mode --version must be v<the [package] version of rust/Cargo.toml>.

OUT_DIR belongs to the builder: it must be absent, empty, or marked by an earlier run of this
script (OUT_DIR/.zeropw-build-release). Anything else is refused before a file is touched.

Every build step runs with an allowlisted environment: ALLOWED_VARIABLES, LC_* and
MACOSX_DEPLOYMENT_TARGET, plus what the script sets itself. Credentials, toolchain overrides
(RUSTFLAGS, CC, OPENSSL_*, ...) and everything else are dropped. Local paths are kept out of
the binaries: rustc remaps the checkout, OUT_DIR, CARGO_HOME and RUSTUP_HOME
(--remap-path-prefix), C compilers do the same (-ffile-prefix-map), and OpenSSL is configured
with the neutral prefix OPENSSL_PREFIX and installed under OUT_DIR with DESTDIR, so its
ENGINESDIR and MODULESDIR name no host path. A binary that still contains the home directory,
the checkout, OUT_DIR, CARGO_HOME, RUSTUP_HOME or /Volumes/ is refused.
"""
import argparse
import hashlib
import os
import re
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import importlib.util

OPENSSL_VERSION = '3.5.9'
OPENSSL_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
OPENSSL_URL = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz'
# Compiled into libcrypto as the base of ENGINESDIR and MODULESDIR; nothing is installed there.
OPENSSL_PREFIX = '/nonexistent/zeropw-openssl'
HOSTS = {('Darwin', 'arm64'): ('aarch64-apple-darwin', 'darwin64-arm64-cc'),
         ('Darwin', 'x86_64'): ('x86_64-apple-darwin', 'darwin64-x86_64-cc'),
         ('Linux', 'aarch64'): ('aarch64-unknown-linux-gnu', 'linux-aarch64'),
         ('Linux', 'x86_64'): ('x86_64-unknown-linux-gnu', 'linux-x86_64')}
# The only inherited variables a release build sees (with LC_*): what the toolchains need to
# find themselves. desktop/scripts/package-macos.py uses the same list.
ALLOWED_VARIABLES = ('PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'LANG', 'TERM',
                     'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'DEVELOPER_DIR')
OUTPUT_MARKER = '.zeropw-build-release'


def run(command, cwd, environment):
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def allowed_environment(inherited, extra=()):
    """The allowlisted part of an inherited environment."""
    return {key: value for key, value in inherited.items()
            if key in ALLOWED_VARIABLES or key in extra or key.startswith('LC_')}


def controlled_environment(inherited):
    # MACOSX_DEPLOYMENT_TARGET is the minimum macOS a caller (package-macos.py) builds for.
    # openssl-sys gives target-prefixed settings precedence over OPENSSL_DIR, and Cargo/rustc
    # linker or flag overrides would bypass the SDK decision: none of them is allowlisted.
    environment = allowed_environment(inherited, ('MACOSX_DEPLOYMENT_TARGET',))
    home = environment.get('HOME') or ''
    if not os.path.isabs(home) or home.rstrip('/') == '':
        # cargo and rustup fall back to the account's home directory without HOME, and that
        # path would then be neither remapped nor caught by the local-path check.
        raise SystemExit('build-release: HOME must be set to an absolute path')
    minimum = environment.get('MACOSX_DEPLOYMENT_TARGET')
    if minimum is not None and not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,2}', minimum):
        raise SystemExit('build-release: MACOSX_DEPLOYMENT_TARGET must be a macOS version such as 11.0')
    return environment


def tool_homes(environment):
    """CARGO_HOME and RUSTUP_HOME as the toolchain resolves them (defaults under HOME)."""
    home = environment.get('HOME')
    cargo = environment.get('CARGO_HOME') or (home and os.path.join(home, '.cargo'))
    rustup = environment.get('RUSTUP_HOME') or (home and os.path.join(home, '.rustup'))
    return cargo, rustup


def remap_pairs(pairs):
    """(local path, neutral path) pairs with their resolved forms, shortest first: rustc and C
    compilers apply the last matching prefix, so the most specific one wins."""
    found = {}
    for path, neutral in pairs:
        if not path:
            continue
        for form in (str(path), os.path.realpath(path)):
            form = form.rstrip('/')
            if form and form not in found:
                found[form] = neutral
    return sorted(found.items(), key=lambda item: len(item[0]))


def remap_environment(pairs):
    """CARGO_ENCODED_RUSTFLAGS and CFLAGS that rewrite each local path prefix to its neutral path."""
    for path, _ in pairs:
        if '=' in path or '\x1f' in path:
            raise SystemExit('build-release: a build path contains "=" and cannot be remapped')
    rust = ['--remap-path-prefix=' + path + '=' + neutral for path, neutral in pairs]
    # CFLAGS is split on whitespace; a path with a space is left to the binary path check.
    c = ['-ffile-prefix-map=' + path + '=' + neutral for path, neutral in pairs if not re.search(r'\s', path)]
    return {'CARGO_ENCODED_RUSTFLAGS': '\x1f'.join(rust), 'CFLAGS': ' '.join(c)}


def local_path_needles(environment, paths):
    """(label, bytes) for each local path that must not occur in a shipped executable."""
    needles = []
    home = (environment.get('HOME') or '').rstrip('/')
    if home:
        needles.append(('the home directory', home))
    cargo, rustup = tool_homes(environment)
    for label, path in [*paths, ('CARGO_HOME', cargo), ('RUSTUP_HOME', rustup)]:
        if path:
            for form in {str(path).rstrip('/'), os.path.realpath(path)}:
                if form and form != '/':
                    needles.append((label, form))
    needles = [(label, (path + '/').encode()) for label, path in needles]
    needles.append(('/Volumes/', b'/Volumes/'))
    # Any account's home, whatever HOME said: /Users/ on macOS, /home/ on Linux.
    needles.append(('an account home (/Users/ or /home/)', b'/Users/'))
    needles.append(('an account home (/Users/ or /home/)', b'/home/'))
    return needles


def path_leaks(data, needles):
    """Labels of the needles that occur in data, each once, in order."""
    labels = []
    for label, needle in needles:
        if needle in data and label not in labels:
            labels.append(label)
    return labels


def verify_paths(binary, needles):
    leaks = path_leaks(binary.read_bytes(), needles)
    if leaks:
        raise SystemExit(f'release binary {binary.name} contains a local path: ' + ', '.join(leaks))


def verify_linkage(binary, system):
    command = ['otool', '-L', str(binary)] if system == 'Darwin' else ['readelf', '-d', str(binary)]
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    dependencies = output.splitlines()[1:] if system == 'Darwin' else output.splitlines()
    for line in dependencies:
        if re.search(r'lib(?:ssl|crypto)[.\-]|/opt/homebrew/|/usr/local/opt/', line, re.I):
            raise SystemExit('release binary has an unexpected dynamic dependency: ' + binary.name)
        # On macOS only the system's own libraries and frameworks may be linked.
        dependency = line.strip()
        if system == 'Darwin' and dependency and not dependency.endswith(':') \
                and not dependency.startswith(('/usr/lib/', '/System/Library/')):
            raise SystemExit('release binary has an unexpected dynamic dependency: ' + binary.name)


def toml_package_version(path):
    section = None
    for line in path.read_text(encoding='utf-8').splitlines():
        header = re.match(r'^\s*\[([^\]]+)\]\s*$', line)
        if header:
            section = header.group(1).strip()
        elif section == 'package':
            value = re.match(r'^\s*version\s*=\s*"([^"]*)"\s*$', line)
            if value:
                return value.group(1)
    return None


def claim_directory(path, marker, owner):
    """Make path a directory this script owns: absent, empty or carrying its marker file.

    Refuses anything else before a file is touched, so a mistyped path never loses data."""
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise SystemExit(f'{owner}: {path} is not a directory')
    mark = path / marker
    if path.is_dir() and any(path.iterdir()) and not (mark.is_file() and not mark.is_symlink()):
        raise SystemExit(f'{owner}: {path} is not empty and was not created by {owner}; '
                         'use a new or empty directory')
    path.mkdir(parents=True, exist_ok=True)
    mark.write_text(f'Created by {owner}; its contents are replaced by later runs.\n')


def load_packager(root):
    spec = importlib.util.spec_from_file_location('package_release', root / 'scripts/package-release.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    return package


def main(argv=None):
    root = pathlib.Path(__file__).resolve().parents[1]
    if (sys.argv[1:] if argv is None else list(argv)) == ['--print-version']:
        # The release version of this checkout, for workflows and scripts: v<rust/Cargo.toml>.
        print('v' + toml_package_version(root / 'rust/Cargo.toml'))
        return 0
    package = load_packager(root)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--target', required=True)
    parser.add_argument('--version', help='archive version v<rust/Cargo.toml version> (archive mode)')
    parser.add_argument('--out-dir', required=True, type=pathlib.Path)
    parser.add_argument('--bin', action='append', dest='bins', metavar='NAME',
                        help='build only this release binary into OUT_DIR/bin; repeatable; no archive')
    args = parser.parse_args(argv)
    if args.bins is None:
        if args.version is None:
            parser.error('--version is required unless --bin selects binaries')
        if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.version):
            parser.error('version must be vMAJOR.MINOR.PATCH')
        product = toml_package_version(root / 'rust/Cargo.toml')
        if args.version != f'v{product}':
            parser.error(f'--version {args.version} is not v{product}, the version of rust/Cargo.toml')
    else:
        if args.version is not None:
            parser.error('--bin builds binaries only; --version names an archive')
        unknown = [name for name in args.bins if name not in package.BINS]
        if unknown or len(set(args.bins)) != len(args.bins):
            parser.error('--bin takes distinct release binaries: ' + ', '.join(package.BINS))
    host = HOSTS.get((platform.system(), platform.machine()))
    if not host or args.target != host[0]:
        parser.error('use a native builder matching the requested target')
    output = args.out_dir.resolve()
    environment = controlled_environment(os.environ)
    claim_directory(output, OUTPUT_MARKER, 'build-release')
    selected = output / 'bin'
    if args.bins is not None:
        # Nothing from an earlier run may pass for this build's output.
        shutil.rmtree(selected, ignore_errors=True)
    work = output / 'openssl-build'
    work.mkdir(exist_ok=True)
    archive = work / ('openssl-' + OPENSSL_VERSION + '.tar.gz')
    if not archive.exists():
        partial = archive.with_suffix('.partial')
        run(['curl', '--disable', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
             '--proto-redir', '=https', '--connect-timeout', '15', '--max-time', '300',
             '--max-filesize', '70000000', OPENSSL_URL, '-o', str(partial)], root, environment)
        partial.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != OPENSSL_SHA256:
        raise SystemExit('OpenSSL source checksum mismatch')
    source = work / ('openssl-' + OPENSSL_VERSION)
    staged = work / 'sdk'
    sdk = staged / OPENSSL_PREFIX.lstrip('/')
    # Always rebuild from the authenticated archive; an existing mutable SDK is not evidence.
    shutil.rmtree(source, ignore_errors=True)
    shutil.rmtree(staged, ignore_errors=True)
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
         '--prefix=' + OPENSSL_PREFIX, '--openssldir=/etc/ssl', '--libdir=lib'], source, environment)
    run(['make', '-j' + str(min(os.cpu_count() or 1, 8))], source, environment)
    run(['make', 'install_sw', 'DESTDIR=' + str(staged)], source, environment)
    cargo_home, rustup_home = tool_homes(environment)
    environment.update(remap_environment(remap_pairs(
        [(cargo_home, '/cargo'), (rustup_home, '/rustup'), (root, '/zeropw'), (output, '/build')])))
    environment.update(OPENSSL_DIR=str(sdk), OPENSSL_STATIC='1',
                       CARGO_TARGET_DIR=str(output / 'cargo-target'))
    names = package.BINS if args.bins is None else tuple(args.bins)
    selection = ['--bins'] if args.bins is None else [part for name in names for part in ('--bin', name)]
    run(['cargo', 'build', '--locked', '--release', '--features', 'bundled-openssl',
         '--target', args.target, '--manifest-path', str(root / 'rust/Cargo.toml'), *selection], root, environment)
    built = output / 'cargo-target' / args.target / 'release'
    needles = local_path_needles(environment, [('the checkout', root), ('the output directory', output)])
    for name in names:
        verify_linkage(built / name, platform.system())
        verify_paths(built / name, needles)
    notices = output / 'THIRD_PARTY_LICENSES.md'
    run(['python3', str(root / 'scripts/dependency-licenses.py'), '--features', 'bundled-openssl',
         '--target', args.target, '--openssl-source', str(source), '--output', str(notices)], root, environment)
    if args.bins is not None:
        selected.mkdir()
        for name in names:
            shutil.copyfile(built / name, selected / name)
            (selected / name).chmod(0o755)
            print(selected / name)
        return
    run(['python3', str(root / 'scripts/package-release.py'), '--version', args.version,
         '--target', args.target, '--bin-dir', str(built),
         '--out-dir', str(output), '--third-party-licenses', str(notices)], root, environment)


if __name__ == '__main__':
    main()
