#!/usr/bin/env python3
"""Package the desktop app as a distributable Apple Silicon .dmg, with no signing credentials.

    python3 desktop/scripts/package-macos.py --work-dir DIR --out-dir DIR

Run it on an Apple Silicon Mac that holds no vault, signing or notarization keys
(docs/releasing.md, "Desktop app"). It:

1. refuses to run when any APPLE_* or other signing/notarization credential variable is set,
   so none can reach npm, Vite, Cargo build scripts or the Tauri bundler;
2. requires a clean tracked tree and builds the committed HEAD from a copy in --work-dir,
   so nothing is written into the checkout;
3. requires every desktop version field to agree and names the release vX.Y.Z after it;
4. runs `npm ci --ignore-scripts`, then scripts/prepare-sidecars.sh (static OpenSSL sidecars
   from scripts/build-release.py --bin, and THIRD_PARTY_LICENSES.md), then
   `tauri build --config src-tauri/tauri.bundle.conf.json --bundles app,dmg` with CI=true
   (no Finder layout step) and the release config's ad-hoc signature ("-");
5. verifies the image: `hdiutil verify`; mounted read-only, the app, the three sidecars,
   LICENSE and THIRD_PARTY_LICENSES.md are present and match their sources; `otool -L` shows
   no Homebrew, /usr/local or OpenSSL library for all four executables, each is arm64 with
   minimum macOS 11.0, ad hoc signed with the hardened runtime; `codesign --verify --deep
   --strict` passes; Info.plist has the version, minimum macOS and Local Network description.
   `spctl -a -vv` is recorded: it rejects an ad-hoc signed app, which is expected;
6. only then moves zeropw-desktop-vX.Y.Z-aarch64-apple-darwin.dmg, its .sha256 ('<hex>  <name>'),
   the notices and the verification log into --out-dir, never replacing an existing file.

Developer ID signing and notarization are a separate procedure on a trusted host
(docs/releasing.md); this script never handles those credentials.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = 'aarch64-apple-darwin'
PRODUCT = 'ZeroPW'
APP = PRODUCT + '.app'
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')
EXECUTABLES = ('zeropw-desktop',) + SIDECARS
MINIMUM_MACOS = '11.0'
RESOURCES = ('LICENSE', 'THIRD_PARTY_LICENSES.md')
# Tauri reads APPLE_* (certificate, password, identity, Apple ID, API key); the others are the
# usual names for notarization and updater signing secrets.
CREDENTIAL_PREFIXES = ('APPLE_', 'TAURI_SIGNING_', 'APP_STORE_CONNECT_', 'ASC_', 'AC_')
CREDENTIAL_MARKERS = ('NOTARY', 'NOTARI', 'CODESIGN', 'KEYCHAIN', 'CERTIFICATE')
CREDENTIAL_NAMES = ('TAURI_PRIVATE_KEY', 'TAURI_KEY_PASSWORD')
UNWANTED_LINKAGE = re.compile(r'/opt/homebrew/|/usr/local/|lib(?:ssl|crypto)[.\-]', re.I)


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
        if (upper.startswith(CREDENTIAL_PREFIXES) or upper in CREDENTIAL_NAMES
                or any(marker in upper for marker in CREDENTIAL_MARKERS)):
            names.append(name)
    return sorted(names)


def build_environment(environ, cargo_target):
    """The build's environment: no credentials (already refused), CI mode, macOS 11.0 minimum."""
    environment = {key: value for key, value in environ.items() if key not in credential_variables(environ)}
    environment.pop('TAURI_BUNDLER_DMG_IGNORE_CI', None)
    environment.update(CI='true', MACOSX_DEPLOYMENT_TARGET=MINIMUM_MACOS, CARGO_TARGET_DIR=str(cargo_target))
    return environment


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


def lock_versions(path, names):
    found = {}
    for block in path.read_text(encoding='utf-8').split('[[package]]')[1:]:
        name = re.search(r'^name = "([^"]+)"$', block, re.M)
        version = re.search(r'^version = "([^"]+)"$', block, re.M)
        if name and version and name.group(1) in names:
            found[name.group(1)] = version.group(1)
    return found


def release_version(source):
    """vX.Y.Z when every desktop version field agrees; otherwise exit naming each field."""
    desktop = source / 'desktop'
    read_json = lambda relative: json.loads((desktop / relative).read_text(encoding='utf-8'))
    lock = read_json('package-lock.json')
    crates = lock_versions(desktop / 'Cargo.lock', ('zeropw-desktop', 'zeropw-desktop-core'))
    fields = {
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
        raise SystemExit('package-macos: the desktop version fields must agree on one MAJOR.MINOR.PATCH:\n' + detail)
    return 'v' + values.pop()


def artifact_names(version):
    base = f'zeropw-desktop-{version}-{TARGET}'
    return {'dmg': base + '.dmg', 'checksum': base + '.dmg.sha256',
            'notices': base + '-THIRD_PARTY_LICENSES.md', 'log': base + '-verification.txt'}


def checksum_line(path):
    digest = hashlib.sha256()
    with path.open('rb') as data:
        for chunk in iter(lambda: data.read(1 << 20), b''):
            digest.update(chunk)
    return f'{digest.hexdigest()}  {path.name}\n'


def linkage_problems(otool_output):
    """Dependencies (otool -L lines after the first) that must not appear in a shipped binary."""
    return [line.strip() for line in otool_output.splitlines()[1:] if UNWANTED_LINKAGE.search(line)]


def minimum_macos(otool_load_commands):
    match = re.search(r'cmd LC_BUILD_VERSION.*?\n\s*minos ([0-9.]+)', otool_load_commands, re.S)
    return match.group(1) if match else None


def inside(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


class Verification:
    def __init__(self, runner, scrub):
        self.runner, self.scrub, self.lines, self.problems = runner, scrub, [], []

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


def verify_image(runner, staging, names, version, source, mount):
    """Check the image as a user receives it. Returns (log text, problems)."""
    scrub = lambda text: text.replace(str(mount), '<mount>').replace(str(staging), '<artifacts>')
    check = Verification(runner, scrub)
    result, _ = check.run(['hdiutil', 'verify', names['dmg']], staging)
    check.require(result.returncode == 0, 'hdiutil verify failed')
    if mount.exists():
        runner.run(['hdiutil', 'detach', str(mount), '-force'], check=False, capture=True)
        shutil.rmtree(mount, ignore_errors=True)
    mount.mkdir(parents=True)
    attach = runner.run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', str(mount),
                         str(staging / names['dmg'])], check=False, capture=True)
    check.lines.append(f'$ hdiutil attach -readonly -nobrowse -noautoopen -mountpoint <mount> {names["dmg"]}\n[exit {attach.returncode}]\n')
    if attach.returncode != 0:
        check.require(False, 'hdiutil attach failed')
        return '\n'.join(check.lines), check.problems
    try:
        contents = mount / APP / 'Contents'
        listing = sorted(path.name for path in mount.iterdir())
        check.lines.append('image root: ' + ', '.join(listing) + '\n')
        check.require((mount / 'Applications').is_symlink(), 'the image has no Applications link')
        for name in EXECUTABLES:
            check.require((contents / 'MacOS' / name).is_file(), f'{APP}/Contents/MacOS/{name} is missing')
        for name in RESOURCES:
            check.require((contents / 'Resources' / name).is_file(), f'{APP}/Contents/Resources/{name} is missing')
        expected = {'LICENSE': source / 'LICENSE', 'THIRD_PARTY_LICENSES.md': staging / names['notices']}
        for name, origin in expected.items():
            shipped = contents / 'Resources' / name
            if shipped.is_file():
                check.require(shipped.read_bytes() == origin.read_bytes(), f'{name} in the app differs from its source')
        for name in EXECUTABLES:
            relative = f'{APP}/Contents/MacOS/{name}'
            if not (contents / 'MacOS' / name).is_file():
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
        result, output = check.run(['codesign', '-dv', '--verbose=4', APP], mount)
        check.require(re.search(r'^Sealed Resources version=2 ', output, re.M) is not None,
                      'the app bundle has no sealed resources')
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
        detach = runner.run(['hdiutil', 'detach', str(mount)], check=False, capture=True)
        if detach.returncode != 0:
            detach = runner.run(['hdiutil', 'detach', str(mount), '-force'], check=False, capture=True)
        check.lines.append(f'$ hdiutil detach <mount>\n[exit {detach.returncode}]\n')
    return '\n'.join(check.lines), check.problems


def main(argv=None, environ=None, runner=None, system=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work-dir', required=True, type=pathlib.Path,
                        help='scratch directory outside the checkout for the source copy and build')
    parser.add_argument('--out-dir', required=True, type=pathlib.Path,
                        help='directory outside the checkout that receives the verified artifacts')
    args = parser.parse_args(argv)
    environ = dict(os.environ if environ is None else environ)
    runner = runner or Runner()

    found = credential_variables(environ)
    if found:
        raise SystemExit('package-macos: refusing to run with signing or notarization credentials in the '
                         'environment (' + ', '.join(found) + '). Package without them; Developer ID signing '
                         'and notarization are a separate step on a trusted host (docs/releasing.md).')
    if (system or (platform.system(), platform.machine())) != ('Darwin', 'arm64'):
        raise SystemExit('package-macos: run on Apple Silicon macOS (target ' + TARGET + ')')
    work, out = args.work_dir.resolve(), args.out_dir.resolve()
    for label, path in (('--work-dir', work), ('--out-dir', out)):
        if inside(path, ROOT) or inside(ROOT, path):
            raise SystemExit(f'package-macos: {label} must be outside the checkout')

    status = runner.run(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=no'], capture=True)
    if status.stdout.strip():
        raise SystemExit('package-macos: commit or discard tracked changes first; the package is built from HEAD')
    commit = runner.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture=True).stdout.strip()
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'source'
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir()
    runner.run(['git', '-C', ROOT, 'archive', '--format=tar', '-o', work / 'source.tar', commit])
    runner.run(['tar', '-xf', work / 'source.tar', '-C', source])
    (work / 'source.tar').unlink()

    version = release_version(source)
    names = artifact_names(version)
    existing = [name for name in names.values() if (out / name).exists() or (out / name).is_symlink()]
    if existing:
        raise SystemExit('package-macos: refusing to replace ' + ', '.join(existing) + ' in ' + str(out))
    print(f'package-macos: {version} from {commit}')

    cargo_target = pathlib.Path(environ.get('CARGO_TARGET_DIR') or work / 'target').resolve()
    environment = build_environment(environ, cargo_target)
    desktop = source / 'desktop'
    built = cargo_target / 'release/bundle/dmg' / f'{PRODUCT}_{version[1:]}_aarch64.dmg'
    notices = desktop / 'src-tauri/notices/THIRD_PARTY_LICENSES.md'
    if built.exists():
        built.unlink()  # an image from an earlier run must not pass for this one
    runner.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=desktop, env=environment)
    runner.run(['sh', 'scripts/prepare-sidecars.sh', TARGET], cwd=desktop, env=environment)
    runner.run([desktop / 'node_modules/.bin/tauri', 'build', '--config', 'src-tauri/tauri.bundle.conf.json',
                '--bundles', 'app,dmg'], cwd=desktop, env=environment)

    for path in (built, notices):
        if not path.is_file():
            raise SystemExit(f'package-macos: the build did not produce {path.name}')
    staging = work / 'artifacts'
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    shutil.copyfile(built, staging / names['dmg'])
    shutil.copyfile(notices, staging / names['notices'])
    (staging / names['checksum']).write_text(checksum_line(staging / names['dmg']))

    log, problems = verify_image(runner, staging, names, version, source, work / 'mnt')
    header = (f'ZeroPW desktop {version} for {TARGET}\nsource commit: {commit}\n'
              f'{(staging / names["checksum"]).read_text()}{checksum_line(staging / names["notices"])}\n')
    (staging / names['log']).write_text(header + log + '\n' + ('RESULT: FAIL\n' if problems else 'RESULT: PASS\n'))
    if problems:
        raise SystemExit('package-macos: verification failed (' + str(staging / names['log']) + '):\n  ' +
                         '\n  '.join(problems))
    out.mkdir(parents=True, exist_ok=True)
    for name in names.values():
        shutil.move(str(staging / name), str(out / name))
        print(out / name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
