#!/usr/bin/env python3
"""Package the desktop app as a distributable Apple Silicon .dmg, with no signing credentials.

    env -i HOME="$HOME" PATH="$PATH" python3 desktop/scripts/package-macos.py \\
        --work-dir DIR --out-dir DIR --tag vX.Y.Z

Run it on an Apple Silicon Mac account that holds no vault, gateway, signer, coordinator,
signing, notarization or release-publishing credentials, or on a host the owner authorized for
the release (docs/releasing.md, "Desktop app" and the release's owner decisions). It filters
environment variables only; it does not keep build code away from the account's files, keychain
or logged-in tools. It:

1. refuses to start while a ZEROPW_* variable or any variable whose name contains TOKEN,
   SECRET, PASSW, PASSPHRASE, _KEY, AUTH, CSC_, P12 or APPLE_ (any case), or another signing,
   notarization or updater name, is set; the message names the variables, never their values.
   Every build step (npm, the sidecar build, Vite, Cargo build scripts, the Tauri bundler) then
   runs with an allowlisted environment: the variables of scripts/build-release.py
   ALLOWED_VARIABLES and LC_*, plus what this script sets (CI, MACOSX_DEPLOYMENT_TARGET,
   CARGO_TARGET_DIR, CARGO_ENCODED_RUSTFLAGS and CFLAGS for path remapping);
2. requires a clean tracked tree and builds the committed HEAD from a copy in --work-dir, which
   must be new, empty or marked by an earlier run (.zeropw-package-macos); --work-dir, --out-dir
   and CARGO_TARGET_DIR (honored when set) must be outside the checkout;
3. requires every desktop version field, rust/Cargo.toml and the zeropw entry of
   rust/Cargo.lock to agree on MAJOR.MINOR.PATCH, names the release vX.Y.Z after it, and with
   --tag refuses any tag other than vX.Y.Z;
4. runs `npm ci --ignore-scripts`, then scripts/prepare-sidecars.sh (static OpenSSL sidecars
   from scripts/build-release.py --bin, and THIRD_PARTY_LICENSES.md), then
   `tauri build --config src-tauri/tauri.bundle.conf.json --bundles app,dmg` with CI=true
   (no Finder layout step) and the release config's ad-hoc signature ("-"). Rust and C source
   paths are remapped (the checkout copy, the work directory, CARGO_TARGET_DIR, CARGO_HOME,
   RUSTUP_HOME); the sidecars build-release.py produced must be byte-identical to the
   src-tauri/binaries files Tauri bundles, and the SHA-256 of both and of the linked app
   executable are recorded;
5. verifies the image: `hdiutil verify`; mounted read-only, the app, the three sidecars,
   LICENSE and THIRD_PARTY_LICENSES.md are present; LICENSE and THIRD_PARTY_LICENSES.md are
   byte-identical to their sources; each of the four executables, with its code signature
   removed (`codesign --remove-signature` on copies), is byte-identical to the binary the build
   produced with its signature removed, except for the __LINKEDIT segment's vmsize, which
   codesign enlarges for its signature and signature removal leaves, and has the same LC_UUID;
   `otool -L` lists only /usr/lib and /System/Library libraries and no libssl or libcrypto;
   each executable is arm64 with minimum macOS 11.0, ad hoc signed with the hardened runtime
   and no entitlements, and contains neither the home directory, the work directory, the
   checkout, CARGO_TARGET_DIR, CARGO_HOME, RUSTUP_HOME nor /Volumes/; the bundle has no
   entitlements, sealed resources and passes `codesign --verify --deep --strict`; Info.plist
   has the version, minimum macOS and Local Network description; the image detaches.
   `spctl -a -vv` is recorded: it rejects an ad-hoc signed app, which is expected;
6. only then copies zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg, its .sha256
   ('<hex>  <name>'), the notices and the verification log into --out-dir, refusing (and
   removing what it created) if any of them exists there, at the start or at copy time.

Developer ID signing and notarization are a separate procedure on a trusted host
(docs/releasing.md); this script never handles those credentials.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import plistlib
import re
import shutil
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = 'aarch64-apple-darwin'
PRODUCT = 'ZeroPW'
APP = PRODUCT + '.app'
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')
EXECUTABLES = ('zeropw-desktop',) + SIDECARS
MINIMUM_MACOS = '11.0'
RESOURCES = ('LICENSE', 'THIRD_PARTY_LICENSES.md')
WORK_MARKER = '.zeropw-package-macos'
# Names that suggest a credential: refused at start, before anything runs.
CREDENTIAL_NAME = re.compile(r'^ZEROPW_|TOKEN|SECRET|PASSW|PASSPHRASE|_KEY|AUTH|CSC_|P12|APPLE_', re.I)
# Tauri reads APPLE_* (certificate, password, identity, Apple ID, API key); the others are the
# usual names for notarization and updater signing secrets.
CREDENTIAL_PREFIXES = ('APPLE_', 'TAURI_SIGNING_', 'APP_STORE_CONNECT_', 'ASC_', 'AC_')
CREDENTIAL_MARKERS = ('NOTARY', 'NOTARI', 'CODESIGN', 'KEYCHAIN', 'CERTIFICATE')
CREDENTIAL_NAMES = ('TAURI_PRIVATE_KEY', 'TAURI_KEY_PASSWORD')
SYSTEM_LIBRARIES = ('/usr/lib/', '/System/Library/')
OPENSSL_LIBRARY = re.compile(r'lib(?:ssl|crypto)[.\-]', re.I)
LC_SEGMENT_64, LC_UUID, LC_CODE_SIGNATURE = 0x19, 0x1b, 0x1d


def load_builder():
    spec = importlib.util.spec_from_file_location('build_release', ROOT / 'scripts/build-release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load_builder()


class Runner:
    """Runs commands; the tests replace it with a fake."""

    def run(self, command, cwd=None, env=None, check=True, capture=False):
        result = subprocess.run([str(part) for part in command], cwd=cwd, env=env, text=True,
                                capture_output=capture)
        if check and result.returncode != 0:
            raise SystemExit(f'package-macos: {pathlib.Path(str(command[0])).name} failed with exit {result.returncode}')
        return result


def credential_variables(environ):
    names = []
    for name in environ:
        upper = name.upper()
        if (CREDENTIAL_NAME.search(name) or upper.startswith(CREDENTIAL_PREFIXES) or upper in CREDENTIAL_NAMES
                or any(marker in upper for marker in CREDENTIAL_MARKERS)):
            names.append(name)
    return sorted(names)


def remap_pairs(environ, work, source, cargo_target):
    cargo_home, rustup_home = BUILDER.tool_homes(environ)
    return BUILDER.remap_pairs([(cargo_home, '/cargo'), (rustup_home, '/rustup'), (ROOT, '/checkout'),
                                (work, '/build'), (source, '/zeropw'), (cargo_target, '/target')])


def build_environment(environ, cargo_target, pairs=()):
    """The build's environment: the allowlist only (credentials were already refused), CI mode,
    macOS 11.0 minimum, the cargo target directory and path remapping."""
    environment = BUILDER.allowed_environment(environ)
    environment.update(CI='true', MACOSX_DEPLOYMENT_TARGET=MINIMUM_MACOS, CARGO_TARGET_DIR=str(cargo_target))
    if pairs:
        environment.update(BUILDER.remap_environment(pairs))
    return environment


toml_package_version = BUILDER.toml_package_version


def lock_versions(path, names):
    found = {}
    for block in path.read_text(encoding='utf-8').split('[[package]]')[1:]:
        name = re.search(r'^name = "([^"]+)"$', block, re.M)
        version = re.search(r'^version = "([^"]+)"$', block, re.M)
        if name and version and name.group(1) in names:
            found[name.group(1)] = version.group(1)
    return found


def release_version(source):
    """vX.Y.Z when every desktop version field and the product version agree; otherwise exit
    naming each field."""
    desktop = source / 'desktop'
    read_json = lambda relative: json.loads((desktop / relative).read_text(encoding='utf-8'))
    lock = read_json('package-lock.json')
    crates = lock_versions(desktop / 'Cargo.lock', ('zeropw-desktop', 'zeropw-desktop-core'))
    product = lock_versions(source / 'rust/Cargo.lock', ('zeropw',))
    fields = {
        'rust/Cargo.toml [package] version': toml_package_version(source / 'rust/Cargo.toml'),
        'rust/Cargo.lock zeropw': product.get('zeropw'),
        'desktop/src-tauri/tauri.conf.json version': read_json('src-tauri/tauri.conf.json').get('version'),
        'desktop/package.json version': read_json('package.json').get('version'),
        'desktop/package-lock.json version': lock.get('version'),
        'desktop/package-lock.json packages[""].version': lock.get('packages', {}).get('', {}).get('version'),
        'desktop/src-tauri/Cargo.toml [package] version': toml_package_version(desktop / 'src-tauri/Cargo.toml'),
        'desktop/core/Cargo.toml [package] version': toml_package_version(desktop / 'core/Cargo.toml'),
        'desktop/Cargo.lock zeropw-desktop': crates.get('zeropw-desktop'),
        'desktop/Cargo.lock zeropw-desktop-core': crates.get('zeropw-desktop-core'),
    }
    if 'version' in read_json('src-tauri/tauri.bundle.conf.json'):
        fields['desktop/src-tauri/tauri.bundle.conf.json version'] = read_json('src-tauri/tauri.bundle.conf.json')['version']
    values = set(fields.values())
    if len(values) != 1 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(next(iter(values)))):
        detail = '\n'.join(f'  {field}: {value}' for field, value in fields.items())
        raise SystemExit('package-macos: the product and desktop version fields must agree on one '
                         'MAJOR.MINOR.PATCH:\n' + detail)
    return 'v' + values.pop()


def artifact_names(version):
    base = f'zeropw-desktop-{version}-{TARGET}'
    return {'dmg': base + '.dmg', 'checksum': base + '.dmg.sha256',
            'notices': base + '-THIRD_PARTY_LICENSES.md', 'log': base + '-verification.txt'}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as data:
        for chunk in iter(lambda: data.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_line(path):
    return f'{sha256(path)}  {path.name}\n'


def linkage_problems(otool_output):
    """Dependencies (otool -L lines after the first) a shipped binary must not have: anything
    outside /usr/lib and /System/Library, and any libssl or libcrypto."""
    problems = []
    for line in otool_output.splitlines()[1:]:
        dependency = line.strip()
        if not dependency or dependency.endswith(':'):
            continue
        if OPENSSL_LIBRARY.search(dependency) or not dependency.startswith(SYSTEM_LIBRARIES):
            problems.append(dependency)
    return problems


def minimum_macos(otool_load_commands):
    match = re.search(r'cmd LC_BUILD_VERSION.*?\n\s*minos ([0-9.]+)', otool_load_commands, re.S)
    return match.group(1) if match else None


def macho_layout(data):
    """(bytes with the __LINKEDIT vmsize zeroed, LC_UUID hex, has LC_CODE_SIGNATURE) for a thin
    little-endian 64-bit Mach-O; None for anything else."""
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        return None
    ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
    end = 32 + sizeofcmds
    if end > len(data):
        return None
    body, offset, uuid, signed = bytearray(data), 32, None, False
    for _ in range(ncmds):
        if offset + 8 > end:
            return None
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > end:
            return None
        if command == LC_SEGMENT_64 and size >= 72 and data[offset + 8:offset + 24].rstrip(b'\0') == b'__LINKEDIT':
            body[offset + 32:offset + 40] = bytes(8)
        elif command == LC_UUID and size >= 24:
            uuid = data[offset + 8:offset + 24].hex()
        elif command == LC_CODE_SIGNATURE:
            signed = True
        offset += size
    return bytes(body), uuid, signed


def unsigned_difference(shipped, built):
    """None when two executables, both with their code signature removed, are the same build;
    otherwise what differs."""
    a, b = macho_layout(shipped), macho_layout(built)
    if a is None or b is None:
        return 'not a thin 64-bit Mach-O executable'
    if a[2] or b[2]:
        return 'still has a code signature after codesign --remove-signature'
    if a[1] is None or a[1] != b[1]:
        return f'LC_UUID {a[1]} differs from the built {b[1]}'
    if a[0] != b[0]:
        return 'bytes differ from the built binary'
    return None


def inside(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


class Verification:
    def __init__(self, runner, staging):
        self.runner, self.lines, self.problems = runner, [], []
        self.paths = [(str(staging), '<artifacts>')]

    def scrub(self, text):
        """Keep local paths out of the log: commands run on relative paths; outputs are rewritten."""
        for path, label in self.paths:
            text = text.replace(path, label)
        return text

    def run(self, command, cwd, note=None):
        result = self.runner.run(command, cwd=cwd, check=False, capture=True)
        output = self.scrub((result.stdout or '') + (result.stderr or ''))
        self.lines.append('$ ' + ' '.join(str(part) for part in command) + (f'    # {note}' if note else ''))
        self.lines.append(output.rstrip('\n') + f'\n[exit {result.returncode}]\n')
        return result, output

    def require(self, condition, problem):
        if not condition:
            self.problems.append(problem)
            self.lines.append('PROBLEM: ' + problem + '\n')


def mount_points(attach_plist):
    try:
        entities = plistlib.loads(attach_plist.encode('utf-8')).get('system-entities', [])
    except (plistlib.InvalidFileException, ValueError, AttributeError):
        return []
    return [entity['mount-point'] for entity in entities if entity.get('mount-point')]


def no_entitlements(stdout):
    """codesign -d --entitlements - --xml prints nothing, or an empty dictionary, without any."""
    if not stdout.strip():
        return True
    try:
        return plistlib.loads(stdout.encode('utf-8')) == {}
    except (plistlib.InvalidFileException, ValueError):
        return False


def verify_image(runner, staging, names, version, source, origins, needles):
    """Check the image as a user receives it. origins maps each executable to the binary the
    build produced; needles are the local paths no executable may contain.
    Returns (log text, problems)."""
    check = Verification(runner, staging)
    result, _ = check.run(['hdiutil', 'verify', names['dmg']], staging)
    check.require(result.returncode == 0, 'hdiutil verify failed')
    # hdiutil picks the mount point under /Volumes; a custom -mountpoint is refused on some volumes.
    attach = runner.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen', '-plist', names['dmg']],
                        cwd=staging, check=False, capture=True)
    mounts = mount_points(attach.stdout or '') if attach.returncode == 0 else []
    for path in mounts:
        check.paths.insert(0, (path, '<mount>'))
    check.lines.append(f'$ hdiutil attach -readonly -nobrowse -noautoopen -plist {names["dmg"]}\n'
                       f'mounted read-only volumes (<mount>): {", ".join(pathlib.Path(p).name for p in mounts) or "none"}\n'
                       + check.scrub(attach.stderr or '').rstrip('\n') + f'\n[exit {attach.returncode}]\n')
    if len(mounts) != 1:
        for path in mounts:
            runner.run(['hdiutil', 'detach', path, '-force'], check=False, capture=True)
        check.require(False, 'hdiutil attach failed or mounted more than one volume')
        return '\n'.join(check.lines), check.problems
    mount = pathlib.Path(mounts[0])
    compare = staging / 'unsigned'
    try:
        contents = mount / APP / 'Contents'
        listing = sorted(path.name for path in mount.iterdir())
        check.lines.append('image root: ' + ', '.join(listing) + '\n')
        check.require((mount / 'Applications').is_symlink(), 'the image has no Applications link')
        for name in EXECUTABLES:
            check.require((contents / 'MacOS' / name).is_file(), f'{APP}/Contents/MacOS/{name} is missing')
        for name in RESOURCES:
            check.require((contents / 'Resources' / name).is_file(), f'{APP}/Contents/Resources/{name} is missing')
        for folder in ('MacOS', 'Resources'):
            for path in sorted((contents / folder).rglob('*')):
                if path.is_file():
                    check.require(path.stat().st_mode & 0o444 == 0o444,
                                  f'{APP}/Contents/{folder}/{path.relative_to(contents / folder)} is not readable by every account')
        expected = {'LICENSE': source / 'LICENSE', 'THIRD_PARTY_LICENSES.md': staging / names['notices']}
        for name, origin in expected.items():
            shipped = contents / 'Resources' / name
            if shipped.is_file():
                same = shipped.read_bytes() == origin.read_bytes()
                check.require(same, f'{name} in the app differs from its source')
                check.lines.append(f'{name}: {"byte-identical to" if same else "DIFFERS from"} its source\n')
        shutil.rmtree(compare, ignore_errors=True)
        compare.mkdir()
        for name in EXECUTABLES:
            relative = f'{APP}/Contents/MacOS/{name}'
            shipped = contents / 'MacOS' / name
            if not shipped.is_file():
                continue
            result, output = check.run(['otool', '-L', relative], mount)
            check.require(result.returncode == 0, f'otool -L failed for {name}')
            bad = linkage_problems(output)
            check.require(not bad, f'{name} links ' + '; '.join(bad))
            result, output = check.run(['lipo', '-archs', relative], mount)
            check.require(output.split() == ['arm64'], f'{name} is not an arm64-only executable')
            result = runner.run(['otool', '-l', relative], cwd=mount, check=False, capture=True)
            found = minimum_macos(result.stdout or '')
            check.lines.append(f'{name}: LC_BUILD_VERSION minos {found}\n')
            check.require(found == MINIMUM_MACOS, f'{name} minimum macOS is {found}, not {MINIMUM_MACOS}')
            result, output = check.run(['codesign', '-dv', '--verbose=4', relative], mount)
            flags = re.search(r'^CodeDirectory .*flags=0x[0-9a-f]+\(([^)]*)\)', output, re.M)
            check.require('Signature=adhoc' in output and flags is not None and {'adhoc', 'runtime'} <= set(flags.group(1).split(',')),
                          f'{name} is not ad hoc signed with the hardened runtime')
            result, _ = check.run(['codesign', '-d', '--entitlements', '-', '--xml', relative], mount)
            check.require(result.returncode == 0 and no_entitlements(result.stdout or ''), f'{name} is signed with entitlements')
            data = shipped.read_bytes()
            leaks = BUILDER.path_leaks(data, needles)
            check.lines.append(f'{name}: local paths: {", ".join(leaks) if leaks else "none"} '
                               f'(checked: {", ".join(dict.fromkeys(label for label, _ in needles))})\n')
            check.require(not leaks, f'{name} contains a local path: ' + ', '.join(leaks))
            # Equal to what the build produced: compare both with their signatures removed.
            origin = origins.get(name)
            if origin is None or not origin.is_file():
                check.require(False, f'{name}: the built binary to compare with is missing')
                continue
            (compare / 'shipped').mkdir(exist_ok=True)
            (compare / 'built').mkdir(exist_ok=True)
            shipped_copy, built_copy = compare / 'shipped' / name, compare / 'built' / name
            shipped_copy.write_bytes(data)
            shutil.copyfile(origin, built_copy)
            stripped = [check.run(['codesign', '--remove-signature', f'{kind}/{name}'], compare)[0].returncode
                        for kind in ('shipped', 'built')]
            difference = unsigned_difference(shipped_copy.read_bytes(), built_copy.read_bytes()) \
                if stripped == [0, 0] else 'codesign --remove-signature failed'
            uuid = (macho_layout(built_copy.read_bytes()) or (None, None))[1]
            check.lines.append(f'{name}: unsigned, {"identical to the built binary" if difference is None else difference}'
                               f' (LC_UUID {uuid})\n')
            check.require(difference is None, f'{name} is not the binary the build produced: {difference}')
        result, output = check.run(['codesign', '-dv', '--verbose=4', APP], mount)
        check.require(re.search(r'^Sealed Resources version=2 ', output, re.M) is not None,
                      'the app bundle has no sealed resources')
        result, _ = check.run(['codesign', '-d', '--entitlements', '-', '--xml', APP], mount)
        check.require(result.returncode == 0 and no_entitlements(result.stdout or ''), f'{APP} is signed with entitlements')
        result, _ = check.run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', APP], mount)
        check.require(result.returncode == 0, 'codesign --verify --deep --strict failed')
        plist = f'{APP}/Contents/Info.plist'
        for key, want in (('CFBundleShortVersionString', version[1:]), ('LSMinimumSystemVersion', MINIMUM_MACOS),
                          ('NSLocalNetworkUsageDescription', None)):
            result, output = check.run(['plutil', '-extract', key, 'raw', '-o', '-', plist], mount)
            value = output.strip() if result.returncode == 0 else None
            check.require(value == want if want is not None else bool(value), f'Info.plist {key} is {value!r}')
        result, _ = check.run(['spctl', '-a', '-vv', '-t', 'exec', APP], mount,
                              note='expected to reject: ad hoc signature, not notarized; recorded, not a failure')
        check.lines.append(f'spctl result: {"accepted" if result.returncode == 0 else "rejected"} (exit {result.returncode})\n')
    finally:
        shutil.rmtree(compare, ignore_errors=True)
        detach = runner.run(['hdiutil', 'detach', str(mount)], check=False, capture=True)
        if detach.returncode != 0:
            detach = runner.run(['hdiutil', 'detach', str(mount), '-force'], check=False, capture=True)
        check.lines.append(f'$ hdiutil detach <mount>\n[exit {detach.returncode}]\n')
        check.require(detach.returncode == 0, 'hdiutil detach failed; the image is still attached')
    return '\n'.join(check.lines), check.problems


def publish(staging, out, names):
    """Copy the artifacts into out without ever replacing a file; on any failure remove what
    this call created and exit."""
    out.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for name in names:
            descriptor = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            created.append(out / name)
            with os.fdopen(descriptor, 'wb') as target, (staging / name).open('rb') as data:
                shutil.copyfileobj(data, target)
    except FileExistsError as error:
        for path in created:
            path.unlink(missing_ok=True)
        raise SystemExit(f'package-macos: refusing to replace {pathlib.Path(error.filename).name} in {out}; '
                         'nothing was published') from None
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    for name in names:
        (staging / name).unlink()
        print(out / name)


def main(argv=None, environ=None, runner=None, system=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work-dir', required=True, type=pathlib.Path,
                        help='scratch directory outside the checkout for the source copy and build')
    parser.add_argument('--out-dir', required=True, type=pathlib.Path,
                        help='directory outside the checkout that receives the verified artifacts')
    parser.add_argument('--tag', required=True,
                        help='the release tag the image is for; must be v<the product and desktop version>')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.tag):
        parser.error('--tag must be vMAJOR.MINOR.PATCH')
    environ = dict(os.environ if environ is None else environ)
    runner = runner or Runner()

    found = credential_variables(environ)
    if found:
        raise SystemExit('package-macos: refusing to run with credential-like variables in the environment ('
                         + ', '.join(found) + '). Start it from a clean environment, for example '
                         '`env -i HOME="$HOME" PATH="$PATH" python3 desktop/scripts/package-macos.py ...`; '
                         'Developer ID signing and notarization are a separate step on a trusted host '
                         '(docs/releasing.md).')
    home = environ.get('HOME') or ''
    if not os.path.isabs(home) or home.rstrip('/') == '':
        raise SystemExit('package-macos: HOME must be set to an absolute path (cargo and rustup would '
                         'otherwise use the account home without the local-path check knowing it)')
    if (system or (platform.system(), platform.machine())) != ('Darwin', 'arm64'):
        raise SystemExit('package-macos: run on Apple Silicon macOS (target ' + TARGET + ')')
    work, out = args.work_dir.resolve(), args.out_dir.resolve()
    cargo_target = pathlib.Path(environ.get('CARGO_TARGET_DIR') or work / 'target').resolve()
    for label, path in (('--work-dir', work), ('--out-dir', out), ('CARGO_TARGET_DIR', cargo_target)):
        if inside(path, ROOT) or inside(ROOT, path):
            raise SystemExit(f'package-macos: {label} must be outside the checkout')

    status = runner.run(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=no'], capture=True)
    if status.stdout.strip():
        raise SystemExit('package-macos: commit or discard tracked changes first; the package is built from HEAD')
    commit = runner.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture=True).stdout.strip()
    BUILDER.claim_directory(work, WORK_MARKER, 'package-macos')
    source = work / 'source'
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir()
    runner.run(['git', '-C', ROOT, 'archive', '--format=tar', '-o', work / 'source.tar', commit])
    runner.run(['tar', '-xf', work / 'source.tar', '-C', source])
    (work / 'source.tar').unlink()

    version = release_version(source)
    if args.tag != version:
        raise SystemExit(f'package-macos: --tag {args.tag} does not match the release version {version} '
                         '(rust/Cargo.toml and every desktop version field)')
    names = artifact_names(version)
    existing = [name for name in names.values() if (out / name).exists() or (out / name).is_symlink()]
    if existing:
        raise SystemExit('package-macos: refusing to replace ' + ', '.join(existing) + ' in ' + str(out))
    print(f'package-macos: {version} from {commit}')

    pairs = remap_pairs(environ, work, source, cargo_target)
    environment = build_environment(environ, cargo_target, pairs)
    desktop = source / 'desktop'
    built = cargo_target / 'release/bundle/dmg' / f'{PRODUCT}_{version[1:]}_aarch64.dmg'
    notices = desktop / 'src-tauri/notices/THIRD_PARTY_LICENSES.md'
    if built.exists():
        built.unlink()  # an image from an earlier run must not pass for this one
    runner.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=desktop, env=environment)
    runner.run(['sh', 'scripts/prepare-sidecars.sh', TARGET], cwd=desktop, env=environment)
    # What Tauri bundles must be what build-release.py built and checked.
    sidecar_build = cargo_target / f'sidecars-{TARGET}' / 'bin'
    origins = {'zeropw-desktop': cargo_target / 'release/zeropw-desktop'}
    sidecar_digests = {}
    for name in SIDECARS:
        bundled, produced = desktop / 'src-tauri/binaries' / f'{name}-{TARGET}', sidecar_build / name
        if not bundled.is_file() or not produced.is_file() or bundled.read_bytes() != produced.read_bytes():
            raise SystemExit(f'package-macos: src-tauri/binaries/{name}-{TARGET} is not the binary build-release.py produced')
        origins[name] = bundled
        sidecar_digests[name] = sha256(produced)
    runner.run([desktop / 'node_modules/.bin/tauri', 'build', '--config', 'src-tauri/tauri.bundle.conf.json',
                '--bundles', 'app,dmg'], cwd=desktop, env=environment)

    for path in (built, notices, origins['zeropw-desktop']):
        if not path.is_file():
            raise SystemExit(f'package-macos: the build did not produce {path.name}')
    for name in SIDECARS:
        if sha256(origins[name]) != sidecar_digests[name]:
            raise SystemExit(f'package-macos: src-tauri/binaries/{name}-{TARGET} changed during the Tauri build')
    built_digests = [f'{sha256(origins["zeropw-desktop"])}  zeropw-desktop (as linked by cargo, before bundling)\n']
    built_digests += [f'{sidecar_digests[name]}  {name} (build-release.py --bin output; the src-tauri/binaries copy '
                      'is identical)\n' for name in SIDECARS]
    staging = work / 'artifacts'
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    shutil.copyfile(built, staging / names['dmg'])
    shutil.copyfile(notices, staging / names['notices'])
    (staging / names['checksum']).write_text(checksum_line(staging / names['dmg']))

    needles = BUILDER.local_path_needles(environment, [('the work directory', work), ('the checkout', ROOT),
                                                       ('CARGO_TARGET_DIR', cargo_target)])
    log, problems = verify_image(runner, staging, names, version, source, origins, needles)
    header = (f'ZeroPW desktop {version} for {TARGET}\nsource commit: {commit}\n'
              f'product version: {version} (rust/Cargo.toml, rust/Cargo.lock and every desktop version field)\n'
              f'release tag: {args.tag} (matches)\n'
              f'{(staging / names["checksum"]).read_text()}{checksum_line(staging / names["notices"])}'
              'built executables, SHA-256 before signing:\n' + ''.join('  ' + line for line in built_digests) + '\n')
    (staging / names['log']).write_text(header + log + '\n' + ('RESULT: FAIL\n' if problems else 'RESULT: PASS\n'))
    if problems:
        raise SystemExit('package-macos: verification failed (' + str(staging / names['log']) + '):\n  ' +
                         '\n  '.join(problems))
    publish(staging, out, list(names.values()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
