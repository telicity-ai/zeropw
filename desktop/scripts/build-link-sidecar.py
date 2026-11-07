#!/usr/bin/env python3
"""Build the zeropw-link daemon the desktop app ships beside zeropw-admin (docs/remote-sync.md §3.1).

    python3 desktop/scripts/build-link-sidecar.py --source DIR --target TRIPLE --out-dir DIR

--source (or ZEROPW_LINK_SRC) is a git checkout of zeropw-link that contains the commit recorded
in desktop/zeropw-link.json. The script:

1. exports exactly that commit with `git archive` into OUT/source, so uncommitted changes,
   untracked files and the checkout's current branch are never built;
2. requires the Go toolchain the record names (`go env GOVERSION`, with GOTOOLCHAIN=local so no
   other toolchain is fetched);
3. builds without the network: GOPROXY=off, GOSUMDB=off, GOFLAGS=-mod=readonly, GOWORK=off and
   GOENV=off (no user go.env), so every module must already be in the module cache and match
   go.sum. Fetch them beforehand on a network you trust, for example
   `git -C DIR archive COMMIT | tar -x -C /tmp/zpl && (cd /tmp/zpl && go mod download)`.
   It builds `./cmd/zeropw-link` like zeropw-link's own scripts/build.sh: CGO_ENABLED=0,
   GOOS/GOARCH from the target, GOARM64=v8.0, GOAMD64=v1, -trimpath, -buildvcs=false and
   -ldflags '-s -w -buildid= -X main.version=<commit prefix>', with the allowlisted
   environment of scripts/build-release.py plus GOPATH, GOMODCACHE and GOCACHE;
4. checks the result: the Go version and module path in its build information, the module list
   against go.sum, and for macOS the minimum system version (LC_BUILD_VERSION) the record names;
5. writes OUT/bin/zeropw-link, OUT/THIRD_PARTY_LICENSES.md (zeropw-link's own LICENSE, the Go
   standard library's LICENSE and PATENTS, and the license files of every module the binary
   lists; a module without one stops the build) and OUT/BUILD.txt (commit, Go version, target,
   modules, SHA-256 of the binary).

OUT must be new, empty or left by an earlier run (.zeropw-build-link). Like every build of
product code, run it on a development machine or CI, never on a host holding real vault,
signing or administrator keys.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DESKTOP = HERE.parent
ROOT = DESKTOP.parent
RECORD = DESKTOP / 'zeropw-link.json'
MARKER = '.zeropw-build-link'
MODULE = 'github.com/telicity-ai/zeropw-link'
PACKAGE = './cmd/zeropw-link'
BINARY = 'zeropw-link'
TARGETS = {
    'aarch64-apple-darwin': ('darwin', 'arm64'),
    'x86_64-apple-darwin': ('darwin', 'amd64'),
    'aarch64-unknown-linux-gnu': ('linux', 'arm64'),
    'x86_64-unknown-linux-gnu': ('linux', 'amd64'),
}
GO_VARIABLES = ('GOPATH', 'GOMODCACHE', 'GOCACHE')
NOTICE_PREFIXES = ('license', 'licence', 'copying', 'notice', 'patents')
MAX_NOTICE_BYTES = 512 * 1024
LC_BUILD_VERSION = 0x32


def load_builder():
    spec = importlib.util.spec_from_file_location('build_release', ROOT / 'scripts/build-release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_record(path=RECORD):
    """The pinned commit, Go version and macOS minimum; exit naming what is wrong."""
    try:
        record = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise SystemExit(f'build-link-sidecar: {path.name} is unreadable ({type(error).__name__})') from None
    problems = []
    if not isinstance(record, dict) or set(record) - {'module', 'commit', 'go', 'macos_minimum', 'note'}:
        raise SystemExit(f'build-link-sidecar: {path.name} must hold module, commit, go, macos_minimum (and a note)')
    if record.get('module') != MODULE:
        problems.append(f'module must be {MODULE}')
    if not re.fullmatch(r'[0-9a-f]{40}', str(record.get('commit', ''))):
        problems.append('commit must be 40 lowercase hex digits')
    if not re.fullmatch(r'go[0-9]+\.[0-9]+(\.[0-9]+)?', str(record.get('go', ''))):
        problems.append('go must be a Go version such as go1.27.3')
    if not re.fullmatch(r'[0-9]+\.[0-9]+', str(record.get('macos_minimum', ''))):
        problems.append('macos_minimum must be MAJOR.MINOR')
    if problems:
        raise SystemExit(f'build-link-sidecar: {path.name}: ' + '; '.join(problems))
    return record


def go_environment(inherited, builder, goos, goarch):
    environment = builder.allowed_environment(inherited, GO_VARIABLES)
    home = environment.get('HOME') or ''
    if not os.path.isabs(home) or home.rstrip('/') == '':
        raise SystemExit('build-link-sidecar: HOME must be set to an absolute path')
    environment.update(GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', GOFLAGS='-mod=readonly', GOWORK='off',
                       GOENV='off', GONOSUMDB='', GOPRIVATE='', GOINSECURE='', GOEXPERIMENT='', CGO_ENABLED='0',
                       GOOS=goos, GOARCH=goarch, GOARM64='v8.0', GOAMD64='v1')
    return environment


def run(command, cwd, environment, capture=False):
    result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=capture)
    if result.returncode != 0:
        detail = ((result.stderr or '') + (result.stdout or '')).strip() if capture else ''
        raise SystemExit(f'build-link-sidecar: {" ".join(command[:3])} failed with exit {result.returncode}'
                         + (f':\n{detail}' if detail else ''))
    return result.stdout if capture else None


def export(source, commit, destination, environment):
    """Exactly `commit` of the checkout, extracted into destination."""
    git = {key: value for key, value in environment.items() if key in ('PATH', 'HOME', 'LANG', 'TMPDIR')}
    git['GIT_CONFIG_NOSYSTEM'] = '1'
    found = subprocess.run(['git', '-C', str(source), 'rev-parse', '--verify', '--quiet', commit + '^{commit}'],
                           env=git, capture_output=True, text=True)
    if found.returncode != 0 or found.stdout.strip() != commit:
        raise SystemExit(f'build-link-sidecar: {source} has no commit {commit} (fetch it into the zeropw-link checkout)')
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    archive = destination.parent / 'source.tar'
    run(['git', '-C', str(source), 'archive', '--format=tar', '-o', str(archive), commit], None, git)
    run(['tar', '-xf', str(archive), '-C', str(destination)], None, git)
    archive.unlink()


def escape_module(text):
    """The module cache's case encoding: an uppercase letter becomes '!' and its lowercase."""
    return re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), text)


def build_info(text):
    """(go version, main module path, [(path, version, sum)]) from `go version -m` output."""
    lines = text.splitlines()
    version = lines[0].split(':', 1)[1].strip() if lines and ':' in lines[0] else None
    main, deps = None, []
    for line in lines[1:]:
        parts = line.strip().split('\t')
        if parts[0] == 'mod' and len(parts) >= 2:
            main = parts[1]
        elif parts[0] == 'dep' and len(parts) >= 3:
            deps.append((parts[1], parts[2], parts[3] if len(parts) > 3 else ''))
        elif parts[0] == '=>':
            raise SystemExit('build-link-sidecar: the binary uses a replaced module; refusing (the pinned go.mod has none)')
    return version, main, deps


def go_sum_entries(path):
    entries = set()
    for line in path.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith('/go.mod'):
            entries.add((parts[0], parts[1], parts[2]))
    return entries


def macos_minimum(data):
    """The minos of LC_BUILD_VERSION in a thin 64-bit little-endian Mach-O, as MAJOR.MINOR."""
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        return None
    ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
    offset, end = 32, 32 + sizeofcmds
    for _ in range(ncmds):
        if offset + 8 > min(end, len(data)):
            return None
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8:
            return None
        if command == LC_BUILD_VERSION and size >= 24:
            minos = struct.unpack_from('<I', data, offset + 12)[0]
            return f'{minos >> 16}.{(minos >> 8) & 0xff}'
        offset += size
    return None


def notice_files(directory):
    found = []
    if directory.is_dir() and not directory.is_symlink():
        for path in sorted(directory.iterdir(), key=lambda p: p.name.lower()):
            if (path.name.lower().startswith(NOTICE_PREFIXES) and path.is_file() and not path.is_symlink()
                    and path.stat().st_size <= MAX_NOTICE_BYTES):
                found.append(path)
    return found


def indent(text):
    return '\n'.join('    ' + line for line in text.splitlines()) + '\n'


def section(heading, files, declared=None):
    names = ', '.join(path.name for path in files)
    text = f'## {heading}\n\n'
    if declared:
        text += f'Declared license: {declared}\n'
    text += f'Notice files: {names}\n\n'
    for path in files:
        text += f'{path.name}:\n\n' + indent(path.read_text(encoding='utf-8', errors='replace')) + '\n'
    return text


def detected_license(files):
    """What a module's own files say for the MPL source list; Go modules declare no license field."""
    text = '\n'.join(path.read_text(encoding='utf-8', errors='replace') for path in files)
    return 'MPL-2.0 (from its license file)' if 'Mozilla Public License Version 2.0' in text else None


def notices(record, target, source, goroot, modcache, deps):
    """The THIRD_PARTY_LICENSES.md text, or exit naming the modules without a notice."""
    parts = [f'# zeropw-link daemon {record["commit"][:12]}\n\n'
             f'Target: {target}.\nzeropw-link commit: {record["commit"]}.\nGo toolchain: {record["go"]}.\n\n'
             'The zeropw-link daemon is built from the commit above with the Go toolchain above. It '
             'contains the Go standard library and the Go modules below, listed with the notice files '
             'they ship. This is an inventory, not a legal opinion.\n\n']
    missing = []
    own = notice_files(source)
    if not own:
        missing.append(MODULE)
    else:
        parts.append(section(f'{MODULE} {record["commit"][:12]}', own))
    std = [path for path in (goroot / 'LICENSE', goroot / 'PATENTS') if path.is_file() and not path.is_symlink()]
    if not any(path.name == 'LICENSE' for path in std):
        missing.append('Go standard library')
    else:
        parts.append(section(f'Go standard library {record["go"]}', std, 'BSD-3-Clause'))
    for path, version, _ in sorted(deps):
        files = notice_files(modcache / f'{escape_module(path)}@{escape_module(version)}')
        if not files:
            missing.append(f'{path} {version}')
            continue
        parts.append(section(f'{path} {version}', files, detected_license(files)))
    if missing:
        raise SystemExit('build-link-sidecar: no license file for: ' + ', '.join(missing) + '; nothing was written')
    return ''.join(parts)


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', type=pathlib.Path, help='zeropw-link git checkout (default: $ZEROPW_LINK_SRC)')
    parser.add_argument('--target', required=True, help='target triple: ' + ', '.join(TARGETS))
    parser.add_argument('--out-dir', required=True, type=pathlib.Path)
    parser.add_argument('--record', type=pathlib.Path, default=RECORD, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    environ = dict(os.environ if environ is None else environ)
    if args.target not in TARGETS:
        parser.error('unsupported target ' + args.target)
    source = args.source or (pathlib.Path(environ['ZEROPW_LINK_SRC']) if environ.get('ZEROPW_LINK_SRC') else None)
    if source is None:
        parser.error('give --source or set ZEROPW_LINK_SRC to a zeropw-link checkout')
    source = source.resolve()
    if not (source / '.git').exists():
        raise SystemExit(f'build-link-sidecar: {source} is not a git checkout of zeropw-link')
    record = read_record(args.record)
    builder = load_builder()
    goos, goarch = TARGETS[args.target]
    environment = go_environment(environ, builder, goos, goarch)
    out = args.out_dir.resolve()
    builder.claim_directory(out, MARKER, 'build-link-sidecar')

    tree = out / 'source'
    export(source, record['commit'], tree, environment)
    if not (tree / 'go.mod').is_file() or not (tree / 'go.sum').is_file():
        raise SystemExit('build-link-sidecar: the pinned commit has no go.mod and go.sum')
    if not re.search(r'^module ' + re.escape(MODULE) + r'$', (tree / 'go.mod').read_text(encoding='utf-8'), re.M):
        raise SystemExit(f'build-link-sidecar: the pinned commit is not module {MODULE}')
    version = run(['go', 'env', 'GOVERSION'], tree, environment, capture=True).strip()
    if version != record['go']:
        raise SystemExit(f'build-link-sidecar: Go is {version or "missing"}, the record needs {record["go"]} '
                         '(GOTOOLCHAIN=local: install that toolchain)')
    goroot = pathlib.Path(run(['go', 'env', 'GOROOT'], tree, environment, capture=True).strip())
    modcache = pathlib.Path(run(['go', 'env', 'GOMODCACHE'], tree, environment, capture=True).strip())

    binary = out / 'bin' / BINARY
    binary.parent.mkdir(exist_ok=True)
    binary.unlink(missing_ok=True)
    # the flags of zeropw-link's own scripts/build.sh, with the pinned commit as the version
    ldflags = f'-ldflags=-s -w -buildid= -X main.version={record["commit"][:12]}'
    run(['go', 'build', '-trimpath', '-buildvcs=false', ldflags, '-o', str(binary), PACKAGE], tree, environment)

    info = run(['go', 'version', '-m', str(binary)], tree, environment, capture=True)
    built_with, main_module, deps = build_info(info)
    problems = []
    if built_with != record['go']:
        problems.append(f'built with {built_with}, not {record["go"]}')
    if main_module != MODULE:
        problems.append(f'main module is {main_module}, not {MODULE}')
    pinned = go_sum_entries(tree / 'go.sum')
    unpinned = [f'{path} {version}' for path, version, digest in deps if (path, version, digest) not in pinned]
    if unpinned:
        problems.append('modules not pinned by go.sum: ' + ', '.join(unpinned))
    data = binary.read_bytes()
    minimum = macos_minimum(data) if goos == 'darwin' else None
    if goos == 'darwin' and minimum != record['macos_minimum']:
        problems.append(f'minimum macOS is {minimum}, the record says {record["macos_minimum"]}')
    needles = builder.local_path_needles(environment, [('the zeropw-link checkout', source), ('the output directory', out),
                                                       ('GOROOT', goroot), ('GOMODCACHE', modcache)])
    leaks = builder.path_leaks(data, needles)
    if leaks:
        problems.append('the binary contains a local path: ' + ', '.join(leaks))
    if problems:
        binary.unlink(missing_ok=True)
        raise SystemExit('build-link-sidecar: ' + '; '.join(problems))
    os.chmod(binary, 0o755)

    text = notices(record, args.target, tree, goroot, modcache, deps)
    (out / 'THIRD_PARTY_LICENSES.md').write_text(text, encoding='utf-8')
    digest = hashlib.sha256(data).hexdigest()
    (out / 'BUILD.txt').write_text(
        f'zeropw-link commit: {record["commit"]}\nGo: {built_with}\ntarget: {args.target} ({goos}/{goarch})\n'
        + (f'minimum macOS: {minimum}\n' if minimum else '')
        + ''.join(f'module: {path} {version} {digest_}\n' for path, version, digest_ in sorted(deps))
        + f'{digest}  {BINARY}\n', encoding='utf-8')
    print(f'build-link-sidecar: {binary} ({args.target}, {built_with}, {len(deps)} modules, sha256 {digest})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
