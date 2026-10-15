#!/usr/bin/env python3
"""Collect declared licenses and root notices from locked Cargo dependencies.

Run on a disposable build runner after dependencies have been fetched. This
creates an inventory, not a legal opinion or a complete nested-source audit.
A package without a root notice fails the run unless --supplement names a
reviewed notice for that exact version (desktop/licenses/supplement.json).
"""
import argparse
import json
import pathlib
import re
import subprocess


def indented(text):
    # Indent instead of fences so original notice text cannot close a fence.
    return '\n'.join('    ' + line for line in text.splitlines()) + '\n'


def supplemental(package, supplement, packages, directory):
    """Reviewed notices for an exact package version that publishes no notice file, or None.

    An entry must repeat the declared license. It names either the root notice files of the one
    locked package from the same source repository (notices_from), or the standard text of one
    license the package is offered under (standard_text: <id>.txt next to the supplement).
    """
    key = f"{package['name']} {package['version']}"
    entry = supplement.get(key)
    if entry is None:
        return None
    if entry.get('license') != package.get('license'):
        raise SystemExit(f'supplement for {key} names license {entry.get("license")!r}; '
                         f'the package declares {package.get("license")!r}')
    repository = package.get('repository') or 'not declared'
    if 'notices_from' in entry:
        donors = [item for item in packages if item['name'] == entry['notices_from']]
        if len(donors) != 1:
            raise SystemExit(f'supplement for {key}: {entry["notices_from"]} is not exactly one locked package')
        donor = donors[0]
        if not package.get('repository') or donor.get('repository') != package.get('repository'):
            raise SystemExit(f'supplement for {key}: {donor["name"]} is not from the same source repository')
        root = pathlib.Path(donor['manifest_path']).parent
        files = sorted(file for file in root.iterdir()
                       if file.name.lower().startswith(('license', 'licence', 'copying', 'notice'))
                       and file.is_file() and not file.is_symlink())
        if not files:
            raise SystemExit(f'supplement for {key}: {donor["name"]} {donor["version"]} has no root notice file')
        note = (f'\nNo notice file is published with this package. Below are the root notice files of '
                f'{donor["name"]} {donor["version"]} from the same source repository ({repository}).\n')
        return note, [(f'{donor["name"]} {donor["version"]}: {file.relative_to(root)}',
                       file.read_text(encoding='utf-8')) for file in files]
    standard = entry.get('standard_text')
    offered = set(re.findall(r'[A-Za-z0-9.+-]+', package.get('license') or '')) - {'OR', 'AND', 'WITH'}
    if not standard or standard not in offered:
        raise SystemExit(f'supplement for {key} needs notices_from or a standard_text the package is offered under')
    text = directory / (standard + '.txt')
    if not text.is_file() or text.is_symlink():
        raise SystemExit(f'supplement for {key}: missing standard text {text.name}')
    holders = ', '.join(re.sub(r'\s*<[^>]*>', '', author).strip() for author in package.get('authors') or [])
    note = (f'\nNo notice file is published with this package; it is used under {standard}, whose standard '
            f'text follows. Copyright holders declared in the package metadata: '
            f'{holders or "none declared"}. Source repository: {repository}.\n')
    return note, [(f'{standard} (standard text)', text.read_text(encoding='utf-8'))]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest-path', default='rust/Cargo.toml')
    p.add_argument('--output', required=True, type=pathlib.Path)
    p.add_argument('--target', required=True, help='release target triple')
    p.add_argument('--include-development', action='store_true', help='also traverse test dependencies')
    p.add_argument('--features', default='', help='Cargo features used by the release build')
    p.add_argument('--openssl-source', type=pathlib.Path, help='verified static SDK source tree')
    p.add_argument('--supplement', type=pathlib.Path,
                   help='reviewed JSON of notices for exact package versions that publish no notice file')
    args = p.parse_args()
    supplement = {}
    if args.supplement is not None:
        supplement = json.loads(args.supplement.read_text(encoding='utf-8'))['packages']
    if 'bundled-openssl' in args.features.split(',') and args.openssl_source is None:
        p.error('bundled release notices require --openssl-source')
    raw = subprocess.check_output(['cargo', 'metadata', '--locked', '--offline',
                                   '--format-version', '1', '--filter-platform', args.target,
                                   '--manifest-path', args.manifest_path, *(['--features', args.features] if args.features else [])])
    metadata = json.loads(raw)
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
                'Package names and versions identify the source; local cache paths are omitted.\n']
    missing = []
    used = set()
    for package in sorted(metadata['packages'], key=lambda item: (item['name'], item['version'])):
        if package['id'] in members or package['id'] not in included:
            continue
        root = pathlib.Path(package['manifest_path']).parent
        sections.append(f"## {package['name']} {package['version']}\n\nDeclared license: {package.get('license') or 'unspecified'}\n")
        notices = {file for file in root.iterdir()
                   if file.name.lower().startswith(('license', 'licence', 'copying', 'notice'))
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
            sections.append('\nNo root notice file found; manual review required.\n')
        for file in sorted(notices):
            sections.append(f'\n### {file.relative_to(root)}\n\n')
            # Indent instead of fences so original notice text cannot close a fence.
            sections.append('\n'.join('    ' + line for line in file.read_text(encoding='utf-8').splitlines()) + '\n')
    if args.openssl_source is not None:
        sections.append('## OpenSSL 3.5.9 (statically linked release SDK)\n')
        for relative in ('LICENSE.txt', 'external/perl/Text-Template-1.56/LICENSE'):
            notice = args.openssl_source / relative
            if not notice.is_file() or notice.is_symlink():
                raise SystemExit('missing static OpenSSL notice: ' + relative)
            sections.append('\n### ' + relative + '\n\n' + '\n'.join(
                '    ' + line for line in notice.read_text(encoding='utf-8').splitlines()) + '\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(sections), encoding='utf-8')
    unused = sorted(set(supplement) - used)
    if unused:
        print('Supplement entries outside this closure: ' + ', '.join(unused))
    if missing:
        print('Missing root notices (manual review required): ' + ', '.join(missing))
        return 1
    print(f'Collected dependency notices into {args.output}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
