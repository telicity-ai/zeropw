#!/usr/bin/env python3
"""Collect declared licenses and root notices from locked Cargo dependencies.

Run on a disposable build runner after dependencies have been fetched. This
creates an inventory, not a legal opinion or a complete nested-source audit.
"""
import argparse
import json
import pathlib
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest-path', default='rust/Cargo.toml')
    p.add_argument('--output', required=True, type=pathlib.Path)
    p.add_argument('--target', required=True, help='release target triple')
    p.add_argument('--include-development', action='store_true', help='also traverse test dependencies')
    args = p.parse_args()
    raw = subprocess.check_output(['cargo', 'metadata', '--locked', '--offline',
                                   '--format-version', '1', '--filter-platform', args.target,
                                   '--manifest-path', args.manifest_path])
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
    for package in sorted(metadata['packages'], key=lambda item: (item['name'], item['version'])):
        if package['id'] in members or package['id'] not in included:
            continue
        root = pathlib.Path(package['manifest_path']).parent
        sections.append(f"## {package['name']} {package['version']}\n\nDeclared license: {package.get('license') or 'unspecified'}\n")
        notices = {file for file in root.iterdir()
                   if file.name.lower().startswith(('license', 'licence', 'copying', 'notice'))
                   and file.is_file() and not file.is_symlink()}
        if package.get('license_file'):
            file = root / package['license_file']
            if file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(root.resolve()):
                notices.add(file)
        if not notices:
            missing.append(f"{package['name']} {package['version']}")
            sections.append('\nNo root notice file found; manual review required.\n')
        for file in sorted(notices):
            sections.append(f'\n### {file.relative_to(root)}\n\n')
            # Indent instead of fences so original notice text cannot close a fence.
            sections.append('\n'.join('    ' + line for line in file.read_text(encoding='utf-8').splitlines()) + '\n')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(sections), encoding='utf-8')
    if missing:
        print('Missing root notices (manual review required): ' + ', '.join(missing))
        return 1
    print(f'Collected dependency notices into {args.output}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
