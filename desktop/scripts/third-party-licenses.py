#!/usr/bin/env python3
"""Write the desktop app's THIRD_PARTY_LICENSES.md, or fail when a notice is missing.

The desktop app redistributes three groups of third-party code, and the file covers each:

1. the Rust crates linked into the app executable (desktop/Cargo.toml, for --target),
   collected by scripts/dependency-licenses.py, with the reviewed notices of
   desktop/licenses/supplement.json for the few crates that publish no notice file;
2. the bundled zeropw-admin, zeropw_session and zeropw-agent: the notices that
   scripts/build-release.py --bin collected for the rust/ closure, including the statically
   linked OpenSSL SDK (--sidecar-notices);
3. the npm packages bundled into the web interface: every package in package-lock.json that is
   not development-only, including the Pretendard and JetBrains Mono fonts (OFL-1.1), read from
   node_modules (run `npm ci` first).

It fetches the desktop crates (`cargo fetch --locked`, which runs no build scripts) so the
offline Cargo metadata is available. Like scripts/dependency-licenses.py, this is an inventory of
declared licenses and the packages' own notice files, not a legal opinion. Nothing is written
unless every package has a notice.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DESKTOP = HERE.parent
ROOT = DESKTOP.parent
NOTICE_PREFIXES = ('license', 'licence', 'copying', 'notice')
# Packages whose notice is not at the package root; each listed file must exist.
NESTED_NPM_NOTICES = {'pretendard': ('dist/LICENSE.txt',)}
OPENSSL_SECTION = re.compile(r'^## OpenSSL [0-9.]+ \(statically linked release SDK\)$', re.M)


def indent(text):
    # Indent instead of fences so original notice text cannot close a fence.
    return '\n'.join('    ' + line for line in text.splitlines()) + '\n'


def demote(text):
    """Nest a generated notices file one heading level below this file's part headings."""
    return '\n'.join('#' + line if line.startswith('#') else line for line in text.splitlines()) + '\n'


def regular_file(path):
    return path.is_file() and not path.is_symlink()


def crate_source(name, version):
    return f'https://crates.io/crates/{name}/{version}'


def npm_source(name, version):
    return f'https://www.npmjs.com/package/{name}/v/{version}'


def mpl_components(text, source):
    """(name, version, source URL) for every package in a notices file declaring MPL."""
    found, current = [], None
    for line in text.splitlines():
        heading = re.match(r'^## (\S+) (\S+)$', line)
        if heading:
            current = heading.groups()
        elif current and line.startswith('Declared license:') and 'MPL' in line:
            found.append((*current, source(*current)))
    return found


def cargo_notices(desktop, target, work):
    manifest = desktop / 'Cargo.toml'
    subprocess.run(['cargo', 'fetch', '--locked', '--manifest-path', str(manifest), '--target', target],
                   check=True)
    output = work / 'desktop-cargo.md'
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/dependency-licenses.py'),
                             '--manifest-path', str(manifest), '--target', target, '--output', str(output),
                             '--supplement', str(desktop / 'licenses/supplement.json')],
                            capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        return None, ['desktop Rust crates: ' + (detail or 'dependency-licenses.py failed')]
    return output.read_text(encoding='utf-8'), []


def sidecar_notices(path, target):
    if not regular_file(path):
        return None, [f'sidecar notices: {path.name} is missing (run scripts/build-release.py --bin first)']
    text = path.read_text(encoding='utf-8')
    problems = []
    if f'Target: {target}.' not in text:
        problems.append(f'sidecar notices: not collected for {target}')
    if not OPENSSL_SECTION.search(text):
        problems.append('sidecar notices: no statically linked OpenSSL notices (not a bundled-openssl build)')
    return text, problems


def npm_notices(desktop):
    lock = json.loads((desktop / 'package-lock.json').read_text(encoding='utf-8'))
    if lock.get('lockfileVersion') not in (2, 3):
        return None, ['package-lock.json: lockfileVersion 2 or 3 is required'], 0
    sections, missing, count = [], [], 0
    for key, entry in sorted(lock.get('packages', {}).items()):
        if not key or entry.get('dev') or entry.get('link'):
            continue
        name = key.rsplit('node_modules/', 1)[-1]
        version = entry.get('version', '')
        directory = desktop / key
        installed = directory / 'package.json'
        if not regular_file(installed):
            missing.append(f'{name} {version}: not installed (run npm ci)')
            continue
        manifest = json.loads(installed.read_text(encoding='utf-8'))
        if manifest.get('name') != name or manifest.get('version') != version:
            missing.append(f'{name} {version}: node_modules does not match package-lock.json')
            continue
        count += 1
        declared = entry.get('license') or manifest.get('license') or 'unspecified'
        sections.append(f'## {name} {version}\n\nDeclared license: {declared}\nSource: {npm_source(name, version)}\n')
        notices = {path for path in directory.iterdir()
                   if path.name.lower().startswith(NOTICE_PREFIXES) and regular_file(path)}
        for relative in NESTED_NPM_NOTICES.get(name, ()):
            nested = directory / relative
            if not regular_file(nested):
                missing.append(f'{name} {version}: {relative} is missing')
            else:
                notices.add(nested)
        if not notices:
            missing.append(f'{name} {version}: no notice file')
        for path in sorted(notices):
            sections.append(f'\n### {path.relative_to(directory).as_posix()}\n\n' +
                            indent(path.read_text(encoding='utf-8')))
    return '\n'.join(sections), missing, count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--target', required=True, help='target triple of the app build')
    parser.add_argument('--sidecar-notices', required=True, type=pathlib.Path,
                        help='THIRD_PARTY_LICENSES.md written by scripts/build-release.py --bin')
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--desktop-dir', type=pathlib.Path, default=DESKTOP, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.target):
        parser.error('bad target triple')
    desktop = args.desktop_dir.resolve()
    # A stale file from an earlier run must not be bundled if this run fails.
    if args.output.is_file() or args.output.is_symlink():
        args.output.unlink()
    with tempfile.TemporaryDirectory() as temporary:
        cargo, problems = cargo_notices(desktop, args.target, pathlib.Path(temporary))
    sidecars, sidecar_problems = sidecar_notices(args.sidecar_notices, args.target)
    npm, npm_problems, npm_count = npm_notices(desktop)
    problems += sidecar_problems + npm_problems
    if problems:
        print('third-party-licenses: missing notices; nothing written', file=sys.stderr)
        for problem in problems:
            print('  ' + problem, file=sys.stderr)
        return 1
    mpl = sorted(set(mpl_components(cargo, crate_source) + mpl_components(sidecars, crate_source) +
                     mpl_components(npm, npm_source)))
    parts = [
        '# ZeroPW desktop app: third-party notices\n',
        f'ZeroPW is under the MIT license (LICENSE, next to this file). The app for {args.target} '
        'also contains the third-party components below, listed with their declared licenses and '
        'the notice files they ship. Package names and versions identify the source; local paths '
        'are omitted. This is an inventory, not a legal opinion.\n',
        '1. The app executable: Rust crates.\n'
        '2. The bundled zeropw-admin, zeropw_session and zeropw-agent: Rust crates and the '
        'statically linked OpenSSL.\n'
        f'3. The web interface: {npm_count} npm packages, including the Pretendard and JetBrains '
        'Mono fonts under the SIL Open Font License 1.1.\n'
        '4. Where to get the source of components under the Mozilla Public License 2.0.\n',
        '# 1. App executable: Rust crates\n', demote(cargo),
        '# 2. Bundled command-line binaries and OpenSSL\n', demote(sidecars),
        '# 3. Web interface: npm packages\n', npm,
        '# 4. Source code of MPL-2.0 components\n',
        'These components are distributed under the Mozilla Public License 2.0 in executable '
        'form, unmodified. Their source code is available at:\n',
        ''.join(f'- {name} {version}: {url}\n' for name, version, url in mpl) or 'None.\n',
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(parts), encoding='utf-8')
    print(f'third-party-licenses: wrote {args.output} ({npm_count} npm packages, {len(mpl)} MPL-2.0 components)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
