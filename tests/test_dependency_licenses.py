"""Verify target closure and original notices using synthetic Cargo metadata and a fake Rust toolchain."""
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'scripts/dependency-licenses.py'
COMMIT = '0123456789abcdef0123456789abcdef01234567'


def toolchain_entry(label, notice):
    return (f'<h3>\U0001F4E6 {label}</h3>\n<p><b>URL:</b> <a href="https://crates.io">crates.io</a></p>\n'
            f'<p><b>License:</b> Apache-2.0 OR MIT</p>\n<p><b>Notices:</b><details><summary><code>LICENSE-MIT</code>'
            f'</summary><pre>\n{notice}\n</pre></details></p>\n')


def fake_rust_toolchain(root, target, release='1.90.0'):
    """A fake rustc (for RUSTC) whose sysroot holds a rustup toolchain's notices and standard library.

    The standard library links hashbrown (version recorded, listed in COPYRIGHT-library.html),
    miniz_oxide (version recorded, listed only in COPYRIGHT.html) and adler2 (version not recorded,
    two versions in COPYRIGHT.html). libtest and getopts are in the sysroot but not linked.
    """
    sysroot = root / ('toolchain-' + release)
    docs = sysroot / 'share/doc/rust'
    (docs / 'licenses').mkdir(parents=True)
    head = ('<!DOCTYPE html>\n<html><body>\n<h1>Copyright notices</h1>\n'
            '<h2 id="short-version">Short version for non-lawyers</h2>\nSynthetic &amp; dual-licensed std.\n'
            '<h2 id="longer-version">Longer version</h2>\n<p>Synthetic longer version.</p>\n'
            '<h2 id="in-tree-files">In-tree files</h2>\n<div><p><b>File/Directory:</b> <code>.</code></p>\n'
            '<p><b>License:</b> Apache-2.0 OR MIT</p>\n<p><b>Copyright:</b> Synthetic Rust Project Developers</p></div>\n'
            '<h2 id="out-of-tree-dependencies">Out-of-tree dependencies</h2>\n')
    (docs / 'COPYRIGHT-library.html').write_text(
        head + toolchain_entry('hashbrown-0.15.0', 'Copyright (c) Synthetic hashbrown authors')
        + toolchain_entry('clap-4.0.0', 'Synthetic clap notice') + '</body></html>\n', encoding='utf-8')
    (docs / 'COPYRIGHT.html').write_text(
        head + toolchain_entry('adler2-2.0.0', 'Synthetic adler2 2.0.0 notice')
        + toolchain_entry('adler2-2.0.1', 'Synthetic adler2 2.0.1 notice')
        + toolchain_entry('miniz_oxide-0.8.0', 'Synthetic miniz_oxide notice')
        + toolchain_entry('miniz_oxide-0.7.0', 'Synthetic old miniz_oxide notice') + '</body></html>\n', encoding='utf-8')
    (docs / 'licenses/MIT.txt').write_text('Synthetic toolchain MIT text\n')
    (docs / 'licenses/Apache-2.0.txt').write_text('Synthetic toolchain Apache text\n')
    (docs / 'licenses/GPL-3.0-or-later.txt').write_text('Synthetic toolchain GPL text\n')
    library = sysroot / 'lib/rustlib' / target / 'lib'
    library.mkdir(parents=True)
    for name, data in (('std', b'x/rust/deps/hashbrown-0.15.0/src/raw.rs\0/rust/deps/miniz_oxide-0.8.0/src/lib.rs'),
                       ('core', b''), ('hashbrown', b'/rust/deps/hashbrown-0.15.0/src/map.rs'), ('adler2', b''),
                       ('miniz_oxide', b''), ('test', b'/rust/deps/getopts-0.2.0/src/lib.rs'), ('getopts', b'')):
        (library / f'lib{name}-0123abcd.rlib').write_bytes(b'!<arch>\n' + data)
    rustc = root / ('rustc-' + release)
    rustc.write_text('#!/bin/sh\n'
                     f'if [ "$1" = -vV ]; then printf "rustc {release}\\nbinary: rustc\\ncommit-hash: {COMMIT}\\n'
                     f'host: {target}\\nrelease: {release}\\n"; exit 0; fi\n'
                     f'if [ "$1" = --print ] && [ "$2" = sysroot ]; then printf "%s\\n" "{sysroot}"; exit 0; fi\n'
                     'exit 1\n')
    rustc.chmod(0o755)
    return rustc


class DependencyLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        packages = []
        for name in ('workspace', 'runtime', 'builder', 'devonly'):
            directory = self.root / name
            directory.mkdir()
            manifest = directory / 'Cargo.toml'
            manifest.write_text('synthetic metadata fixture')
            if name != 'devonly':
                directory.joinpath('license-mit').write_text('Synthetic upstream notice for ' + name)
            packages.append({'id': name, 'name': name, 'version': '1.0.0',
                             'manifest_path': str(manifest), 'license': 'MIT', 'license_file': None})
        (self.root / 'workspace/Cargo.lock').write_text('synthetic lockfile\n')
        metadata = {'workspace_members': ['workspace'], 'workspace_root': str(self.root / 'workspace'),
                    'packages': packages,
                    'resolve': {'nodes': [
                        {'id': 'workspace', 'deps': [
                            {'pkg': 'runtime', 'dep_kinds': [{'kind': None}]},
                            {'pkg': 'builder', 'dep_kinds': [{'kind': 'build'}]},
                            {'pkg': 'devonly', 'dep_kinds': [{'kind': 'dev'}]}]},
                        *({'id': name, 'deps': []} for name in ('runtime', 'builder', 'devonly'))]}}
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        self.root.joinpath('cargo').write_text('#!/bin/sh\ncat "' + str(self.root / 'metadata.json') + '"\n')
        self.root.joinpath('cargo').chmod(0o755)
        self.rustc = fake_rust_toolchain(self.root, 'aarch64-unknown-linux-gnu')
        self.output = self.root / 'notices.md'

    def run_tool(self, *args):
        env = dict(os.environ, RUSTC=str(self.rustc))
        env['PATH'] = str(self.root) + os.pathsep + env['PATH']
        return subprocess.run(['python3', str(SCRIPT), '--target', 'aarch64-unknown-linux-gnu',
                               '--manifest-path', str(self.root / 'workspace/Cargo.toml'),
                               '--output', str(self.output), *args], env=env, capture_output=True, text=True)

    def run_ok(self, *args):
        result = self.run_tool(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.output.read_text(encoding='utf-8')

    def run_refused(self, *args):
        self.output.write_text('stale notices from an earlier run')
        result = self.run_tool(*args)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        return result

    def test_notices_are_readable_by_every_account(self):
        old = os.umask(0o077)  # a strict umask must not make the shipped notices owner-only
        try:
            self.run_ok()
        finally:
            os.umask(old)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)

    def test_runtime_and_build_notices_retained_without_cache_paths(self):
        notices = self.run_ok()
        self.assertIn('## runtime 1.0.0', notices)
        self.assertIn('## builder 1.0.0', notices)
        self.assertIn('Synthetic upstream notice for runtime', notices)
        self.assertNotIn('## devonly', notices)
        self.assertNotIn(str(self.root), notices)
        lock = hashlib.sha256((self.root / 'workspace/Cargo.lock').read_bytes()).hexdigest()
        self.assertIn(f'\nCargo.lock SHA-256: {lock}.\n', notices)

    def test_rust_standard_library_notice_comes_from_the_toolchain(self):
        notices = self.run_ok()
        std = notices[notices.index('## Rust standard library'):]
        for fragment in (f'## Rust standard library (rustc 1.90.0, {COMMIT})',
                         'built for aarch64-unknown-linux-gnu',
                         '### COPYRIGHT-library.html: in-tree files', 'Synthetic & dual-licensed std.',
                         'License: Apache-2.0 OR MIT', 'Copyright: Synthetic Rust Project Developers',
                         '### COPYRIGHT-library.html: hashbrown-0.15.0', 'Copyright (c) Synthetic hashbrown authors',
                         '### COPYRIGHT.html: miniz_oxide-0.8.0', 'Synthetic miniz_oxide notice',
                         '### COPYRIGHT.html: adler2-2.0.0', '### COPYRIGHT.html: adler2-2.0.1',
                         'does not record the version of adler2',
                         '### licenses/Apache-2.0.txt', 'Synthetic toolchain Apache text',
                         '### licenses/MIT.txt', 'Synthetic toolchain MIT text'):
            self.assertIn(fragment, std)
        for absent in ('clap', 'getopts', 'Synthetic old miniz_oxide notice', 'GPL', '<p>', '&amp;'):
            self.assertNotIn(absent, std)
        self.assertNotIn(str(self.root), notices)

    def test_standard_library_notice_is_required(self):
        sysroot = self.root / 'toolchain-1.90.0'
        (sysroot / 'share/doc/rust/COPYRIGHT.html').unlink()
        result = self.run_refused()
        self.assertIn('share/doc/rust/COPYRIGHT.html', result.stderr)
        (sysroot / 'lib/rustlib/aarch64-unknown-linux-gnu/lib/libextra_dep-0123abcd.rlib').write_bytes(b'')
        (sysroot / 'share/doc/rust/COPYRIGHT.html').write_text('<html><body></body></html>')
        result = self.run_refused()
        self.assertIn('no toolchain notice entry for adler2, extra_dep, miniz_oxide 0.8.0', result.stderr)
        (sysroot / 'share/doc/rust/COPYRIGHT-library.html').unlink()
        self.assertIn('COPYRIGHT-library.html', self.run_refused().stderr)
        self.rustc.write_text('#!/bin/sh\nexit 1\n')
        self.assertIn('rustc -vV', self.run_refused().stderr)

    def test_missing_notice_writes_nothing(self):
        result = self.run_refused('--include-development')
        self.assertIn('devonly 1.0.0', result.stdout)
        self.assertEqual([path.name for path in self.root.iterdir() if path.name.startswith('.notices')], [])

    def test_symlink_notice_is_not_read(self):
        license_path = self.root / 'runtime/license-mit'
        license_path.unlink()
        outside = self.root / 'outside'
        outside.write_text('do not read this content')
        license_path.symlink_to(outside)
        result = self.run_refused()
        self.assertIn('runtime 1.0.0', result.stdout)

    def supplement(self, entries, repositories=None):
        metadata = json.loads(self.root.joinpath('metadata.json').read_text())
        for package in metadata['packages']:
            package['repository'] = (repositories or {}).get(package['name'])
            package['authors'] = ['Synthetic Holder <holder@example.invalid>']
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        directory = self.root / 'reviewed'
        directory.mkdir(exist_ok=True)
        directory.joinpath('MIT.txt').write_text('Synthetic standard MIT text')
        directory.joinpath('MPL-2.0.txt').write_text('Synthetic standard MPL text')
        directory.joinpath('supplement.json').write_text(json.dumps({'packages': entries}))
        return ('--include-development', '--supplement', str(directory / 'supplement.json'))

    def test_supplement_standard_text_carries_the_reviewed_copyright_lines(self):
        entry = {'license': 'MIT', 'standard_text': 'MIT', 'source': 'LICENSE at the published commit.',
                 'copyright': ['Copyright (c) Original Author', 'Copyright 2026 Fork Maintainer']}
        notices = self.run_ok(*self.supplement({'devonly 1.0.0': entry}))
        self.assertIn('### Copyright notice and MIT license text\n\n    Copyright (c) Original Author\n'
                      '    Copyright 2026 Fork Maintainer\n    \n    Synthetic standard MIT text', notices)
        self.assertIn('Reviewed: LICENSE at the published commit.', notices)
        self.assertIn('Authors in the package metadata: Synthetic Holder.', notices)
        self.assertNotIn('holder@example.invalid', notices)
        self.assertNotIn('none declared', notices)
        metadata = json.loads(self.root.joinpath('metadata.json').read_text())
        metadata['packages'][3]['authors'] = []
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        notices = self.run_ok('--include-development', '--supplement', str(self.root / 'reviewed/supplement.json'))
        self.assertIn('Reviewed: LICENSE at the published commit. Source repository:', notices)
        self.assertIn('    Copyright (c) Original Author\n', notices)

    def test_supplement_without_upstream_holder_is_refused_for_texts_that_need_one(self):
        for entry, message in (({'license': 'MIT', 'standard_text': 'MIT', 'source': 's', 'copyright': []},
                                'needs the upstream copyright lines'),
                               ({'license': 'MIT', 'standard_text': 'MIT', 'source': 's'}, 'copyright must list'),
                               ({'license': 'MIT', 'standard_text': 'MIT', 'source': 's', 'copyright': ['Synthetic Holder']},
                                'copyright must list'),
                               ({'license': 'MIT', 'standard_text': 'MIT', 'copyright': ['Copyright Holder']},
                                'must say where its notice was reviewed')):
            with self.subTest(entry=entry):
                self.assertIn(message, self.run_refused(*self.supplement({'devonly 1.0.0': entry})).stderr)
        mpl = {'license': 'MPL-2.0', 'standard_text': 'MPL-2.0', 'source': 'no license file upstream.', 'copyright': []}
        metadata = json.loads(self.root.joinpath('metadata.json').read_text())
        metadata['packages'][3]['license'] = 'MPL-2.0'
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        notices = self.run_ok(*self.supplement({'devonly 1.0.0': mpl}))
        self.assertIn('Upstream names no copyright holder', notices)
        self.assertIn('### MPL-2.0 (standard text)', notices)

    def test_supplement_notices_from_one_exact_version_of_the_same_repository(self):
        same = {'devonly': 'https://example.invalid/repo', 'runtime': 'https://example.invalid/repo'}
        entry = {'devonly 1.0.0': {'license': 'MIT', 'notices_from': 'runtime 1.0.0', 'source': 'same text upstream.'}}
        notices = self.run_ok(*self.supplement(entry, same))
        self.assertIn('### runtime 1.0.0: license-mit', notices)
        self.assertEqual(notices.count('Synthetic upstream notice for runtime'), 2)
        result = self.run_refused(*self.supplement(entry, dict(same, runtime='https://example.invalid/other')))
        self.assertIn('not from the same source repository', result.stderr)
        stale = {'devonly 1.0.0': {'license': 'MIT', 'notices_from': 'runtime 0.9.0', 'source': 'same text upstream.'}}
        self.assertIn('runtime 0.9.0 is not exactly one locked package', self.run_refused(*self.supplement(stale, same)).stderr)

    def test_supplement_must_match_the_declared_license_and_an_offered_text(self):
        for entry, message in (({'license': 'Apache-2.0', 'standard_text': 'MIT'}, 'the package declares'),
                               ({'license': 'MIT', 'standard_text': 'Apache-2.0', 'source': 's'}, 'offered under')):
            with self.subTest(message=message):
                result = self.run_refused(*self.supplement({'devonly 1.0.0': entry}))
                self.assertIn(message, result.stderr)
        entry = {'license': 'MIT', 'standard_text': 'MIT', 'source': 's', 'copyright': ['Copyright Holder']}
        result = self.run_refused(*self.supplement({'devonly 0.9.0': entry}))
        self.assertIn('devonly 1.0.0', result.stdout)
        self.assertIn('Supplement entries outside this closure: devonly 0.9.0', result.stdout)

if __name__ == '__main__':
    unittest.main()
