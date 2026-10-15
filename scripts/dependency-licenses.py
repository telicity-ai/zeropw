#!/usr/bin/env python3
"""Collect declared licenses and root notices from locked Cargo dependencies.

Run on a disposable build runner after dependencies have been fetched. This
creates an inventory, not a legal opinion or a complete nested-source audit.
A package without a root notice fails the run unless --supplement names a
reviewed notice for that exact version (desktop/licenses/supplement.json).

Every executable built from the closure also links the Rust standard library
statically, so the output ends with the toolchain's own notices for it: the
toolchain that builds the release (RUSTC, else rustc on PATH, as Cargo picks it)
ships them in share/doc/rust. The in-tree terms come from COPYRIGHT-library.html;
the out-of-tree crates compiled into the standard library for --target are found
in the toolchain's own library files and their entries copied from
COPYRIGHT-library.html, or from COPYRIGHT.html when the library file leaves
them out.

The output records the SHA-256 of the workspace Cargo.lock. Nothing is written
unless every package has a notice, and the file is replaced only on success.
"""
import argparse
import hashlib
import html
import html.parser
import json
import os
import pathlib
import re
import subprocess
import tempfile

NOTICE_PREFIXES = ('license', 'licence', 'copying', 'notice')
# Standard texts whose "above copyright notice" must name a holder; a reviewed supplement entry
# that uses one of them has to supply the upstream copyright lines.
NEEDS_HOLDER = {'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Zlib'}
# Standard-library crates from the Rust source tree itself (covered by the in-tree terms) and
# sysroot crates that only test harnesses, procedural macros or coverage builds link.
STD_IN_TREE = {'core', 'alloc', 'std', 'panic_unwind', 'panic_abort', 'unwind', 'compiler_builtins',
               'std_detect', 'rustc_std_workspace_core', 'rustc_std_workspace_alloc'}
STD_NOT_LINKED = {'test', 'getopts', 'unicode_width', 'proc_macro', 'rustc_literal_escaper',
                  'profiler_builtins', 'sysroot', 'rustc_std_workspace_std'}
# Out-of-tree sources in the distributed standard library are remapped to /rust/deps/<name>-<version>.
DEPS_PATH = re.compile(rb'/rust/deps/([A-Za-z0-9_.-]+?)-([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]*)?)/')
STD_HEADING = '## Rust standard library'


def indented(text):
    # Indent instead of fences so original notice text cannot close a fence.
    return '\n'.join('    ' + line for line in text.splitlines()) + '\n'


def crate_key(name):
    return name.replace('-', '_')


class TextFromHtml(html.parser.HTMLParser):
    """Plain text of the toolchain's generated notice HTML; <pre> blocks are kept verbatim."""

    BLOCKS = {'p', 'div', 'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li', 'br', 'details', 'summary', 'table', 'tr'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines, self.line, self.pre = [], [], 0

    def flush(self):
        text = re.sub(r'\s+', ' ', ''.join(self.line)).strip()
        if text:
            self.lines.append(text)
        self.line = []

    def handle_starttag(self, tag, attrs):
        if tag == 'pre':
            self.flush()
            self.pre += 1
            self.lines.append('')
        elif tag in self.BLOCKS and not self.pre:
            self.flush()
            if tag in ('h1', 'h2', 'h3', 'h4', 'div'):
                self.lines.append('')

    def handle_endtag(self, tag):
        if tag == 'pre' and self.pre:
            self.pre -= 1
            self.lines.append('')
        elif tag in self.BLOCKS and not self.pre:
            self.flush()

    def handle_data(self, data):
        if self.pre:
            self.lines.append(data.strip('\n'))
        else:
            self.line.append(data)

    @classmethod
    def convert(cls, markup):
        parser = cls()
        parser.feed(markup)
        parser.close()
        parser.flush()
        text = '\n'.join(line.rstrip() for line in '\n'.join(parser.lines).splitlines())
        return re.sub(r'\n{3,}', '\n\n', text).strip('\n') + '\n'


def notice_entries(markup):
    """{(crate key, version): (name-version, HTML)} for the out-of-tree entries of a notice file."""
    entries = {}
    for match in re.finditer(r'<h3>\U0001F4E6 ([^<]+?)</h3>(.*?)(?=<h3>\U0001F4E6 |</body>|\Z)', markup, re.S):
        label = html.unescape(match.group(1)).strip()
        split = re.fullmatch(r'(.+?)-([0-9]+\.[0-9]+\.[0-9]+\S*)', label)
        if split:
            entries[(crate_key(split.group(1)), split.group(2))] = (label, match.group(0))
    return entries


def rust_std_notice(target):
    """The toolchain's notice section for the standard library linked into executables for target."""
    rustc = os.environ.get('RUSTC') or 'rustc'
    try:
        version = subprocess.run([rustc, '-vV'], check=True, capture_output=True, text=True).stdout
        sysroot = subprocess.run([rustc, '--print', 'sysroot'], check=True,
                                 capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit('Rust standard library notice: rustc -vV / --print sysroot failed')
    fields = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
    release, commit = fields.get('release', ''), fields.get('commit-hash', '')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\S*', release) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise SystemExit('Rust standard library notice: rustc -vV names no release and commit hash')
    docs = pathlib.Path(sysroot) / 'share/doc/rust'

    def read(name):
        path = docs / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f'Rust standard library notice: the toolchain has no share/doc/rust/{name} '
                             '(install the toolchain with rustup, which ships it in the rustc component)')
        return path.read_text(encoding='utf-8')

    library = read('COPYRIGHT-library.html')
    intree = re.search(r'<h2 id="short-version">.*?(?=<h2 id="out-of-tree-dependencies">)', library, re.S)
    if not intree or 'id="in-tree-files"' not in intree.group(0):
        raise SystemExit('Rust standard library notice: COPYRIGHT-library.html has no in-tree section')
    libdir = pathlib.Path(sysroot) / 'lib/rustlib' / target / 'lib'
    rlibs = sorted(path for path in libdir.glob('lib*.rlib') if path.is_file() and not path.is_symlink())
    if not rlibs:
        raise SystemExit(f'Rust standard library notice: the toolchain has no standard library for {target}')
    linked = {}  # crate key -> versions recorded in the compiled library (empty: not recorded)
    for rlib in rlibs:
        crate = re.fullmatch(r'lib(.+)-[0-9a-f]+\.rlib', rlib.name)
        crate = crate.group(1) if crate else rlib.stem[3:]
        if crate in STD_NOT_LINKED:
            continue
        if crate not in STD_IN_TREE:
            linked.setdefault(crate_key(crate), set())
        for name, found in DEPS_PATH.findall(rlib.read_bytes()):
            linked.setdefault(crate_key(name.decode()), set()).add(found.decode())
    catalogs = [('COPYRIGHT-library.html', notice_entries(library)), ('COPYRIGHT.html', None)]
    selected, unlisted = [], []
    for crate, versions in sorted(linked.items()):
        for index, (title, entries) in enumerate(catalogs):
            if entries is None:  # the whole-toolchain file is large; read it only when needed
                entries = notice_entries(read(title))
                catalogs[index] = (title, entries)
            keys = [key for key in sorted(entries) if key[0] == crate and (not versions or key[1] in versions)]
            if keys and (not versions or {key[1] for key in keys} == versions):
                selected += [(title, entries[key]) for key in keys]
                break
        else:
            unlisted.append(crate + (' ' + ', '.join(sorted(versions)) if versions else ''))
    if unlisted:
        raise SystemExit('Rust standard library notice: no toolchain notice entry for ' + ', '.join(unlisted))
    parts = [TextFromHtml.convert(intree.group(0))]
    sections = [('COPYRIGHT-library.html: in-tree files', parts[0])]
    for title, (label, markup) in selected:
        text = TextFromHtml.convert(markup)
        parts.append(text)
        sections.append((f'{title}: {label}', text))
    named = set()
    for text in parts:
        for line in re.findall(r'^License: (.+)$', text, re.M):
            named.update(re.findall(r'[A-Za-z0-9.+-]+', line))
    for name in sorted(named - {'OR', 'AND', 'WITH'}):
        path = docs / 'licenses' / (name + '.txt')
        if path.is_file() and not path.is_symlink():
            sections.append((f'licenses/{name}.txt', path.read_text(encoding='utf-8')))
    unrecorded = sorted(crate for crate, versions in linked.items() if not versions)
    body = [f'{STD_HEADING} (rustc {release}, {commit})\n',
            f'Statically linked into every executable built for {target} with this toolchain. The notices '
            'below are the toolchain\'s own, from share/doc/rust: the in-tree terms of COPYRIGHT-library.html, '
            'the entries for the out-of-tree crates compiled into the standard library for this target '
            '(from COPYRIGHT-library.html, or COPYRIGHT.html where the library file leaves one out; they are '
            'found in the compiled library itself, whatever its "In libstd" field says), and the license '
            'texts they name.' +
            (f' The compiled library does not record the version of {", ".join(unrecorded)}; every version '
             'the toolchain notice lists is included.' if unrecorded else '') + '\n']
    body += [f'\n### {title}\n\n' + indented(text) for title, text in sections]
    return '\n'.join(body)


def supplemental(package, supplement, packages, directory):
    """Reviewed notices for an exact package version that publishes no notice file, or None.

    An entry must repeat the declared license and give its source: where the reviewed notice was
    checked against upstream (the repository's license files at the commit the version was
    published from). It names either the root notice files of one exact locked package from the
    same source repository (notices_from: "name version"), or the standard text of one license the
    package is offered under (standard_text: <id>.txt next to the supplement) with the upstream
    copyright lines (copyright). A standard text whose "above copyright notice" names a holder
    (MIT, BSD, ISC, Zlib) cannot be used without them.
    """
    key = f"{package['name']} {package['version']}"
    entry = supplement.get(key)
    if entry is None:
        return None
    if entry.get('license') != package.get('license'):
        raise SystemExit(f'supplement for {key} names license {entry.get("license")!r}; '
                         f'the package declares {package.get("license")!r}')
    if not isinstance(entry.get('source'), str) or not entry['source'].strip():
        raise SystemExit(f'supplement for {key} must say where its notice was reviewed (source)')
    repository = package.get('repository') or 'not declared'
    if 'notices_from' in entry:
        donors = [item for item in packages if f"{item['name']} {item['version']}" == entry['notices_from']]
        if len(donors) != 1:
            raise SystemExit(f'supplement for {key}: {entry["notices_from"]} is not exactly one locked package')
        donor = donors[0]
        if not package.get('repository') or donor.get('repository') != package.get('repository'):
            raise SystemExit(f'supplement for {key}: {donor["name"]} is not from the same source repository')
        root = pathlib.Path(donor['manifest_path']).parent
        files = sorted(file for file in root.iterdir()
                       if file.name.lower().startswith(NOTICE_PREFIXES)
                       and file.is_file() and not file.is_symlink())
        if not files:
            raise SystemExit(f'supplement for {key}: {donor["name"]} {donor["version"]} has no root notice file')
        note = (f'\nNo notice file is published with this package. Below are the root notice files of '
                f'{donor["name"]} {donor["version"]} from the same source repository ({repository}). '
                f'Reviewed: {entry["source"]}\n')
        return note, [(f'{donor["name"]} {donor["version"]}: {file.relative_to(root)}',
                       file.read_text(encoding='utf-8')) for file in files]
    standard = entry.get('standard_text')
    offered = set(re.findall(r'[A-Za-z0-9.+-]+', package.get('license') or '')) - {'OR', 'AND', 'WITH'}
    if not standard or standard not in offered:
        raise SystemExit(f'supplement for {key} needs notices_from or a standard_text the package is offered under')
    text = directory / (standard + '.txt')
    if not text.is_file() or text.is_symlink():
        raise SystemExit(f'supplement for {key}: missing standard text {text.name}')
    holders = entry.get('copyright')
    if not isinstance(holders, list) or not all(isinstance(line, str) and line.startswith('Copyright ')
                                                for line in holders):
        raise SystemExit(f'supplement for {key}: copyright must list the upstream copyright lines')
    if standard in NEEDS_HOLDER and not holders:
        raise SystemExit(f'supplement for {key}: the {standard} text needs the upstream copyright lines')
    authors = ', '.join(re.sub(r'\s*<[^>]*>', '', author).strip() for author in package.get('authors') or [])
    note = (f'\nNo notice file is published with this package; it is used under {standard}. '
            + ('The copyright lines below were reviewed against upstream and precede the standard text. '
               if holders else 'Upstream names no copyright holder; the standard text follows. ')
            + f'Reviewed: {entry["source"]} ' + (f'Authors in the package metadata: {authors}. ' if authors else '')
            + f'Source repository: {repository}.\n')
    body = text.read_text(encoding='utf-8')
    if holders:
        return note, [(f'Copyright notice and {standard} license text', '\n'.join(holders) + '\n\n' + body)]
    return note, [(f'{standard} (standard text)', body)]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--manifest-path', default='rust/Cargo.toml')
    p.add_argument('--output', required=True, type=pathlib.Path)
    p.add_argument('--target', required=True, help='release target triple')
    p.add_argument('--include-development', action='store_true', help='also traverse test dependencies')
    p.add_argument('--features', default='', help='Cargo features used by the release build')
    p.add_argument('--openssl-source', type=pathlib.Path, help='verified static SDK source tree')
    p.add_argument('--supplement', type=pathlib.Path,
                   help='reviewed JSON of notices for exact package versions that publish no notice file')
    args = p.parse_args()
    # A file from an earlier or failed run must not pass for this run's output.
    if args.output.is_file() or args.output.is_symlink():
        args.output.unlink()
    supplement = {}
    if args.supplement is not None:
        supplement = json.loads(args.supplement.read_text(encoding='utf-8'))['packages']
    if 'bundled-openssl' in args.features.split(',') and args.openssl_source is None:
        p.error('bundled release notices require --openssl-source')
    raw = subprocess.check_output(['cargo', 'metadata', '--locked', '--offline',
                                   '--format-version', '1', '--filter-platform', args.target,
                                   '--manifest-path', args.manifest_path, *(['--features', args.features] if args.features else [])])
    metadata = json.loads(raw)
    lock = pathlib.Path(metadata['workspace_root']) / 'Cargo.lock'
    if not lock.is_file() or lock.is_symlink():
        raise SystemExit('Cargo.lock is missing next to the workspace manifest')
    members = set(metadata['workspace_members'])
    nodes = {node['id']: node for node in metadata['resolve']['nodes']}
    included = set()
    pending = list(members)
    while pending:
        package_id = pending.pop()
        if package_id in included:
            continue
        included.add(package_id)
        for dependency in nodes[package_id]['deps']:
            if args.include_development or any(kind['kind'] != 'dev' for kind in dependency['dep_kinds']):
                pending.append(dependency['pkg'])
    sections = ['# Third-party dependency licenses\n',
                'Generated from the locked Cargo metadata and original dependency notice files.\n'
                f'Target: {args.target}. Build/runtime dependency closure; development dependencies '
                f'{"included" if args.include_development else "excluded"}.\n'
                f'Cargo.lock SHA-256: {hashlib.sha256(lock.read_bytes()).hexdigest()}.\n'
                'Package names and versions identify the source; local cache paths are omitted.\n']
    missing = []
    used = set()
    for package in sorted(metadata['packages'], key=lambda item: (item['name'], item['version'])):
        if package['id'] in members or package['id'] not in included:
            continue
        root = pathlib.Path(package['manifest_path']).parent
        sections.append(f"## {package['name']} {package['version']}\n\nDeclared license: {package.get('license') or 'unspecified'}\n")
        notices = {file for file in root.iterdir()
                   if file.name.lower().startswith(NOTICE_PREFIXES)
                   and file.is_file() and not file.is_symlink()}
        # openssl-src bundles OpenSSL and build-time Text::Template notices;
        # wrapper-crate root licenses alone do not cover those embedded sources.
        if package['name'] == 'openssl-src':
            for relative in ('openssl/LICENSE.txt', 'openssl/external/perl/Text-Template-1.56/LICENSE'):
                nested = root / relative
                if not nested.is_file() or nested.is_symlink():
                    raise SystemExit('missing bundled OpenSSL notice: ' + relative)
                notices.add(nested)
        if package.get('license_file'):
            file = root / package['license_file']
            if file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(root.resolve()):
                notices.add(file)
        supplied = None if notices or args.supplement is None else supplemental(
            package, supplement, metadata['packages'], args.supplement.parent)
        if supplied is not None:
            used.add(f"{package['name']} {package['version']}")
            sections.append(supplied[0])
            for title, text in supplied[1]:
                sections.append(f'\n### {title}\n\n' + indented(text))
        elif not notices:
            missing.append(f"{package['name']} {package['version']}")
        for file in sorted(notices):
            sections.append(f'\n### {file.relative_to(root)}\n\n' + indented(file.read_text(encoding='utf-8')))
    unused = sorted(set(supplement) - used)
    if unused:
        print('Supplement entries outside this closure: ' + ', '.join(unused))
    if missing:
        print('Missing root notices (manual review required); nothing written: ' + ', '.join(missing))
        return 1
    sections.append(rust_std_notice(args.target))
    if args.openssl_source is not None:
        sections.append('## OpenSSL 3.5.9 (statically linked release SDK)\n')
        for relative in ('LICENSE.txt', 'external/perl/Text-Template-1.56/LICENSE'):
            notice = args.openssl_source / relative
            if not notice.is_file() or notice.is_symlink():
                raise SystemExit('missing static OpenSSL notice: ' + relative)
            sections.append('\n### ' + relative + '\n\n' + indented(notice.read_text(encoding='utf-8')))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=args.output.parent, delete=False,
                                     prefix='.' + args.output.name + '.') as partial:
        partial.write('\n'.join(sections))
    os.replace(partial.name, args.output)
    print(f'Collected dependency notices into {args.output}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
