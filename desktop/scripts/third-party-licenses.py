#!/usr/bin/env python3
"""Write the desktop app's THIRD_PARTY_LICENSES.md, or fail when a notice is missing.

The desktop app redistributes four groups of third-party code, and the file covers each:

1. the Rust crates linked into the app executable (desktop/Cargo.toml, for --target),
   collected by scripts/dependency-licenses.py, with the reviewed notices of
   desktop/licenses/supplement.json for the few crates that publish no notice file;
2. the bundled zeropw-admin, zeropw_session and zeropw-agent: the notices that
   scripts/build-release.py --bin collected for the rust/ closure, including the statically
   linked OpenSSL SDK (--sidecar-notices). They must be complete and current: collected for
   --target from the rust/Cargo.lock next to this desktop directory, with the same Rust
   toolchain as this run;
3. the Rust standard library linked into all four executables: the toolchain's own notices,
   which scripts/dependency-licenses.py adds to both collections; they must agree;
4. the web interface: every package in package-lock.json that is not development-only, read
   from node_modules (run `npm ci` first), plus the development-only build tools whose own
   code the production build emits into dist (Rolldown's runtime helper, Vite's module-preload
   polyfill). The reviewed npm entries of supplement.json name the notice files of each
   OFL font (Pretendard's adds the upstream notice that names the fonts it is built from) and
   pin the build tools' versions.

It fetches the desktop crates (`cargo fetch --locked`, which runs no build scripts) so the
offline Cargo metadata is available. Like scripts/dependency-licenses.py, this is an inventory of
declared licenses and the packages' own notice files, not a legal opinion. Nothing is written
unless every package has a notice.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DESKTOP = HERE.parent
ROOT = DESKTOP.parent
NOTICE_PREFIXES = ('license', 'licence', 'copying', 'notice')
OPENSSL_SECTION = re.compile(r'^## OpenSSL [0-9.]+ \(statically linked release SDK\)$', re.M)
STD_SECTION = re.compile(r'^## Rust standard library \(.*?(?=^## |\Z)', re.M | re.S)
INCOMPLETE = 'manual review required'
# The tools that write dist: each locked version needs a reviewed npm entry naming the code of its
# own that it emits (bundler_runtime), found by checking a source-mapped production build.
BUILD_TOOLS = ('rolldown', 'vite')


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


def split_std(text, label):
    """(notices without the Rust standard library section, that section), or a problem."""
    sections = STD_SECTION.findall(text)
    if len(sections) != 1:
        return text, None, f'{label}: no Rust standard library notice (collect it again with the current scripts/dependency-licenses.py)'
    return STD_SECTION.sub('', text), sections[0].rstrip('\n') + '\n', None


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


def sidecar_notices(path, target, rust_lock):
    if not regular_file(path):
        return None, [f'sidecar notices: {path.name} is missing (run scripts/build-release.py --bin first)']
    text = path.read_text(encoding='utf-8')
    problems = []
    if f'Target: {target}.' not in text:
        problems.append(f'sidecar notices: not collected for {target}')
    if not OPENSSL_SECTION.search(text):
        problems.append('sidecar notices: no statically linked OpenSSL notices (not a bundled-openssl build)')
    if INCOMPLETE in text:
        problems.append('sidecar notices: incomplete (a crate has no notice; run scripts/build-release.py --bin again)')
    recorded = re.search(r'^Cargo\.lock SHA-256: ([0-9a-f]{64})\.$', text, re.M)
    current = hashlib.sha256(rust_lock.read_bytes()).hexdigest() if regular_file(rust_lock) else None
    if not recorded or recorded.group(1) != current:
        problems.append('sidecar notices: not collected from the current rust/Cargo.lock (run scripts/build-release.py --bin again)')
    return text, problems


def excerpt(text, review):
    """The reviewed leading section of a notice file (up to the `to` heading), or None if it moved."""
    start, end = review['from'], '\n' + review['to']
    if not text.startswith(start) or text.count(end) != 1:
        return None
    return text[:text.index(end) + 1]


def npm_notices(desktop, reviewed):
    """(markdown, problems, runtime package count, build tool count) for the web interface."""
    lock = json.loads((desktop / 'package-lock.json').read_text(encoding='utf-8'))
    if lock.get('lockfileVersion') not in (2, 3):
        return None, ['package-lock.json: lockfileVersion 2 or 3 is required'], 0, 0
    packages = lock.get('packages', {})
    locked = {}
    for key, entry in packages.items():
        if key and not entry.get('link'):
            locked.setdefault(key.rsplit('node_modules/', 1)[-1], []).append((key, entry))
    problems, runtime, tools = [], [], []
    for item in sorted(reviewed):
        name, _, version = item.rpartition(' ')
        if not any(entry.get('version') == version for _, entry in locked.get(name, [])):
            problems.append(f'supplement npm entry {item} matches no locked package (review it again)')
    for name in BUILD_TOOLS:
        for _, entry in locked.get(name, []):
            if not (reviewed.get(f'{name} {entry.get("version")}') or {}).get('bundler_runtime'):
                problems.append(f'{name} {entry.get("version")}: check which of its own code a source-mapped '
                                'production build emits and review it in desktop/licenses/supplement.json')
    for key, entry in sorted(packages.items()):
        if not key or entry.get('link'):
            continue
        name = key.rsplit('node_modules/', 1)[-1]
        version = entry.get('version', '')
        review = reviewed.get(f'{name} {version}')
        if not entry.get('dev'):
            runtime.append((key, name, version, entry, review))
        elif review is not None and review.get('bundler_runtime'):
            tools.append((key, name, version, entry, review))
    sections = []

    def collect(key, name, version, entry, review, lines):
        directory = desktop / key
        installed = directory / 'package.json'
        if not regular_file(installed):
            problems.append(f'{name} {version}: not installed (run npm ci)')
            return
        manifest = json.loads(installed.read_text(encoding='utf-8'))
        if manifest.get('name') != name or manifest.get('version') != version:
            problems.append(f'{name} {version}: node_modules does not match package-lock.json')
            return
        declared = entry.get('license') or manifest.get('license') or 'unspecified'
        if 'OFL' in declared and review is None:
            problems.append(f'{name} {version}: an OFL font needs a reviewed npm entry in desktop/licenses/supplement.json '
                            '(its copyright and Reserved Font Name statements, including those of the fonts it derives from)')
            return
        if review is not None and review.get('license') != declared:
            problems.append(f'supplement npm entry {name} {version} names license {review.get("license")!r}; '
                            f'the package declares {declared!r}')
            return
        notices = {path.relative_to(directory).as_posix(): path for path in directory.iterdir()
                   if path.name.lower().startswith(NOTICE_PREFIXES) and regular_file(path)}
        if review is not None:
            listed = review.get('notices') or []
            unlisted = sorted(set(notices) - set(listed))
            if unlisted:
                problems.append(f'{name} {version}: notice files {", ".join(unlisted)} are not in its reviewed entry')
            for relative in listed:
                if not regular_file(directory / relative):
                    problems.append(f'{name} {version}: {relative} is missing')
                else:
                    notices[relative] = directory / relative
        if not notices:
            problems.append(f'{name} {version}: no notice file')
            return
        sections.append(f'## {name} {version}\n\nDeclared license: {declared}\nSource: {npm_source(name, version)}\n')
        sections.extend(lines)
        section = (review or {}).get('excerpt')
        for relative, path in sorted(notices.items()):
            text = path.read_text(encoding='utf-8')
            if section and relative == section['file']:
                part = excerpt(text, section)
                if part is None:
                    problems.append(f'{name} {version}: {relative} no longer starts with the reviewed section')
                    continue
                sections.append(f'\n### {relative} (its first section, up to "{section["to"]}")\n\n' + indent(part))
            else:
                sections.append(f'\n### {relative}\n\n' + indent(text))
        if review is not None and review.get('upstream_notice'):
            upstream = desktop / 'licenses' / review['upstream_notice']
            if not regular_file(upstream):
                problems.append(f'{name} {version}: reviewed upstream notice {upstream.name} is missing')
            else:
                sections.append(f'\n### Upstream notice ({upstream.name})\n\n' + indent(upstream.read_text(encoding='utf-8')))

    for item in runtime:
        review = item[4]
        lines = [f'\nReviewed: {review["source"]}\n'] if review is not None else []
        collect(*item, lines)
    if tools:
        sections.append('## Build tools whose own code is emitted into the web interface\n\n'
                        'These development-only packages are not bundled as modules, but the production build '
                        'writes some of their own code into dist/assets/index-*.js.\n')
    for key, name, version, entry, review in tools:
        collect(key, name, version, entry, review,
                [f'\nEmitted code: {review["bundler_runtime"]}\nReviewed: {review["source"]}\n'])
    return '\n'.join(sections), problems, len(runtime), len(tools)


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
    reviewed = json.loads((desktop / 'licenses/supplement.json').read_text(encoding='utf-8')).get('npm', {})
    with tempfile.TemporaryDirectory() as temporary:
        cargo, problems = cargo_notices(desktop, args.target, pathlib.Path(temporary))
    sidecars, sidecar_problems = sidecar_notices(args.sidecar_notices, args.target, desktop.parent / 'rust/Cargo.lock')
    npm, npm_problems, npm_count, tool_count = npm_notices(desktop, reviewed)
    problems += sidecar_problems + npm_problems
    standard = None
    if cargo is not None and sidecars is not None:
        cargo, standard, problem = split_std(cargo, 'desktop Rust crates')
        sidecars, sidecar_standard, sidecar_problem = split_std(sidecars, 'sidecar notices')
        problems += [problem for problem in (problem, sidecar_problem) if problem]
        if standard and sidecar_standard and standard != sidecar_standard:
            problems.append('sidecar notices: collected with a different Rust toolchain or target than this run')
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
        '3. The Rust standard library, statically linked into all four executables.\n'
        f'4. The web interface: {npm_count} npm packages, including the Pretendard and JetBrains '
        f'Mono fonts under the SIL Open Font License 1.1, and code from {tool_count} build tools.\n'
        '5. Where to get the source of components under the Mozilla Public License 2.0.\n',
        '# 1. App executable: Rust crates\n', demote(cargo),
        '# 2. Bundled command-line binaries and OpenSSL\n', demote(sidecars),
        '# 3. Rust standard library\n', demote(standard),
        '# 4. Web interface: npm packages\n', npm,
        '# 5. Source code of MPL-2.0 components\n',
        'These components are distributed under the Mozilla Public License 2.0 in executable '
        'form, unmodified. Their source code is available at:\n',
        ''.join(f'- {name} {version}: {url}\n' for name, version, url in mpl) or 'None.\n',
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=args.output.parent, delete=False,
                                     prefix='.' + args.output.name + '.') as partial:
        partial.write('\n'.join(parts))
    os.replace(partial.name, args.output)
    print(f'third-party-licenses: wrote {args.output} ({npm_count} npm packages, {tool_count} build tools, '
          f'{len(mpl)} MPL-2.0 components)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
