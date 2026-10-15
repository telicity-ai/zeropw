"""desktop/scripts/third-party-licenses.py with synthetic Cargo metadata, lockfile, node_modules and toolchain."""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'desktop/scripts/third-party-licenses.py'
DEPENDENCY_LICENSES = ROOT / 'scripts/dependency-licenses.py'
TARGET = 'aarch64-apple-darwin'
REVIEWED_PRETENDARD = ROOT / 'desktop/licenses/pretendard-LICENSE-0189074f.txt'
# packages/pretendard/dist/LICENSE.txt at orioncactus/pretendard 0189074fdad117a5e360aad00a59b47225429c31.
PRETENDARD_UPSTREAM_SHA256 = '82e9c8a4b203261f10ddba1296422d64914ff3d4b7bd8a12896d03f0f088d70a'


def _toolchain_fixture():
    """fake_rust_toolchain from test_dependency_licenses.py, loaded by path (no test classes are imported)."""
    spec = importlib.util.spec_from_file_location('dependency_license_fixture',
                                                  pathlib.Path(__file__).with_name('test_dependency_licenses.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.fake_rust_toolchain


fake_rust_toolchain = _toolchain_fixture()


def crate(root, name, version, license_name, notice, repository=None):
    directory = root / 'registry' / f'{name}-{version}'
    directory.mkdir(parents=True)
    (directory / 'Cargo.toml').write_text('synthetic crate manifest')
    if notice:
        (directory / notice).write_text(f'Synthetic upstream notice for {name}\n')
    return {'id': name, 'name': name, 'version': version, 'license': license_name, 'license_file': None,
            'manifest_path': str(directory / 'Cargo.toml'), 'authors': ['Synthetic Author <author@example.invalid>'],
            'repository': repository or 'https://example.invalid/' + name}


def metadata(workspace, member, packages, edges):
    nodes = [{'id': package['id'], 'deps': [{'pkg': dep, 'dep_kinds': [{'kind': None}]} for dep in edges.get(package['id'], [])]}
             for package in packages]
    return {'workspace_members': [member], 'workspace_root': str(workspace), 'packages': packages,
            'resolve': {'nodes': nodes}}


class DesktopLicenseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.desktop = self.root / 'desktop'
        self.desktop.mkdir()
        (self.desktop / 'Cargo.toml').write_text('synthetic workspace manifest')
        (self.desktop / 'Cargo.lock').write_text('synthetic desktop lockfile\n')
        desktop_packages = [crate(self.root, 'zeropw-desktop', '0.1.0', 'MIT', None),
                            crate(self.root, 'tauri', '2.0.0', 'Apache-2.0 OR MIT', 'LICENSE-MIT'),
                            crate(self.root, 'option-ext', '0.2.0', 'MPL-2.0', 'LICENSE.md'),
                            crate(self.root, 'objc2', '0.6.5', 'MIT', None)]
        (self.root / 'desktop-metadata.json').write_text(json.dumps(metadata(
            self.desktop, 'zeropw-desktop', desktop_packages,
            {'zeropw-desktop': ['tauri'], 'tauri': ['option-ext', 'objc2']})))
        # The sidecars' workspace (rust/), collected the way scripts/build-release.py --bin does.
        self.rust = self.root / 'rust'
        self.rust.mkdir()
        (self.rust / 'Cargo.toml').write_text('synthetic workspace manifest')
        (self.rust / 'Cargo.lock').write_text('synthetic rust lockfile\n')
        rust_packages = [crate(self.root, 'zeropw', '0.1.0', 'MIT', None),
                         crate(self.root, 'openssl', '0.10.0', 'Apache-2.0', 'LICENSE')]
        (self.root / 'rust-metadata.json').write_text(json.dumps(metadata(self.rust, 'zeropw', rust_packages,
                                                                          {'zeropw': ['openssl']})))
        self.openssl = self.root / 'openssl-3.5.9'
        (self.openssl / 'external/perl/Text-Template-1.56').mkdir(parents=True)
        (self.openssl / 'LICENSE.txt').write_text('Synthetic OpenSSL notice\n')
        (self.openssl / 'external/perl/Text-Template-1.56/LICENSE').write_text('Synthetic Text::Template notice\n')
        # objc2 publishes no notice file; the reviewed supplement supplies the standard MIT text.
        licenses = self.desktop / 'licenses'
        licenses.mkdir()
        (licenses / 'MIT.txt').write_text('Synthetic standard MIT text\n')
        (licenses / 'pretendard-LICENSE-0189074f.txt').write_bytes(REVIEWED_PRETENDARD.read_bytes())
        (licenses / 'polyfill-origin.txt').write_text('Copyright (C) Synthetic polyfill origin\n')
        self.supplement = {
            'packages': {'objc2 0.6.5': {'license': 'MIT', 'standard_text': 'MIT', 'source': 'synthetic review.',
                                         'copyright': ['Copyright (c) Synthetic Original Author']}},
            'npm': {
                'pretendard 1.3.9': {'license': 'OFL-1.1', 'notices': ['dist/LICENSE.txt'],
                                     'upstream_notice': 'pretendard-LICENSE-0189074f.txt', 'source': 'synthetic font review.'},
                '@fontsource/jetbrains-mono 5.3.0': {'license': 'OFL-1.1', 'notices': ['LICENSE'],
                                                     'source': 'synthetic font review.'},
                'rolldown 1.2.0': {'license': 'MIT', 'notices': ['LICENSE', 'THIRD-PARTY-LICENSE'],
                                   'upstream_notice': 'polyfill-origin.txt',
                                   'bundler_runtime': 'Synthetic runtime helper.', 'source': 'synthetic bundle review.'},
                'vite 8.0.0': {'license': 'MIT', 'notices': ['LICENSE.md'],
                               'excerpt': {'file': 'LICENSE.md', 'from': '# Vite core license',
                                           'to': '# Licenses of bundled dependencies'},
                               'bundler_runtime': 'Synthetic preload polyfill.', 'source': 'synthetic bundle review.'}}}
        self.write_supplement()
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'cargo').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(self.root / 'cargo.log') + '"\n'
                                     'if [ "$1" = fetch ]; then exit 0; fi\n'
                                     'case "$*" in *' + str(self.rust / 'Cargo.toml') + '*) cat "' +
                                     str(self.root / 'rust-metadata.json') + '";; *) cat "' +
                                     str(self.root / 'desktop-metadata.json') + '";; esac\n')
        (tools / 'cargo').chmod(0o755)
        self.rustc = fake_rust_toolchain(self.root, TARGET)
        self.environment = dict(os.environ, RUSTC=str(self.rustc),
                                PATH=str(tools) + os.pathsep + os.environ.get('PATH', os.defpath))
        self.lock = {'name': 'zeropw-desktop', 'version': '0.1.0', 'lockfileVersion': 3, 'packages': {
            '': {'name': 'zeropw-desktop', 'version': '0.1.0'},
            'node_modules/react': {'version': '19.0.0', 'license': 'MIT'},
            'node_modules/pretendard': {'version': '1.3.9', 'license': 'OFL-1.1'},
            'node_modules/@fontsource/jetbrains-mono': {'version': '5.3.0', 'license': 'OFL-1.1'},
            'node_modules/typescript': {'version': '5.0.0', 'license': 'Apache-2.0', 'dev': True},
            'node_modules/rolldown': {'version': '1.2.0', 'license': 'MIT', 'dev': True},
            'node_modules/vite': {'version': '8.0.0', 'license': 'MIT', 'dev': True}}}
        self.write_lock()
        for key, entry in self.lock['packages'].items():
            if not key:
                continue
            directory = self.desktop / key
            directory.mkdir(parents=True)
            name = key.split('node_modules/', 1)[1]
            (directory / 'package.json').write_text(json.dumps({'name': name, 'version': entry['version']}))
        modules = self.desktop / 'node_modules'
        (modules / 'react/LICENSE').write_text('Synthetic React MIT notice\n')
        (modules / 'typescript/LICENSE.txt').write_text('Synthetic TypeScript notice\n')
        (modules / '@fontsource/jetbrains-mono/LICENSE').write_text(
            'Copyright 2020 The JetBrains Mono Project Authors (synthetic)\nSynthetic OFL text\n')
        (modules / 'pretendard/dist').mkdir()
        (modules / 'pretendard/dist/LICENSE.txt').write_text(
            'Copyright (c) 2021, Kil Hyung-jin (synthetic), with Reserved Font Name Pretendard.\nSynthetic OFL text\n')
        (modules / 'rolldown/LICENSE').write_text('Synthetic Rolldown MIT notice\n')
        (modules / 'rolldown/THIRD-PARTY-LICENSE').write_text('Synthetic esbuild and Rollup notices\n')
        (modules / 'vite/LICENSE.md').write_text('# Vite core license\nSynthetic Vite MIT notice\n\n'
                                                 '# Licenses of bundled dependencies\nSynthetic bundled dependency notice\n')
        self.sidecars = self.root / 'sidecars/THIRD_PARTY_LICENSES.md'
        self.collect_sidecars()
        self.output = self.root / 'out/THIRD_PARTY_LICENSES.md'

    def write_supplement(self):
        (self.desktop / 'licenses/supplement.json').write_text(json.dumps(self.supplement))

    def write_lock(self):
        (self.desktop / 'package-lock.json').write_text(json.dumps(self.lock))

    def collect_sidecars(self, rustc=None):
        result = subprocess.run([sys.executable, str(DEPENDENCY_LICENSES), '--manifest-path', str(self.rust / 'Cargo.toml'),
                                 '--target', TARGET, '--features', 'bundled-openssl', '--openssl-source', str(self.openssl),
                                 '--output', str(self.sidecars)],
                                env=dict(self.environment, RUSTC=str(rustc or self.rustc)), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_tool(self):
        return subprocess.run([sys.executable, str(SCRIPT), '--target', TARGET, '--sidecar-notices', str(self.sidecars),
                               '--output', str(self.output), '--desktop-dir', str(self.desktop)],
                              env=self.environment, capture_output=True, text=True)

    def run_ok(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.output.read_text(encoding='utf-8')

    def assert_refused(self, result, *fragments):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)

    def test_all_groups_and_mpl_sources_are_collected(self):
        text = self.run_ok()
        for fragment in ('# 1. App executable: Rust crates', '### tauri 2.0.0', 'Synthetic upstream notice for tauri',
                         '# 2. Bundled command-line binaries and OpenSSL', '### openssl 0.10.0',
                         '### OpenSSL 3.5.9 (statically linked release SDK)', 'Synthetic OpenSSL notice',
                         '# 3. Rust standard library', '### Rust standard library (rustc 1.90.0,',
                         'Copyright (c) Synthetic hashbrown authors',
                         '# 4. Web interface: npm packages', '## pretendard 1.3.9', 'Declared license: OFL-1.1',
                         '### dist/LICENSE.txt', 'Synthetic React MIT notice', '3 npm packages', 'code from 2 build tools',
                         '- option-ext 0.2.0: https://crates.io/crates/option-ext/0.2.0',
                         '### objc2 0.6.5', '    Copyright (c) Synthetic Original Author\n    \n    Synthetic standard MIT text'):
            self.assertIn(fragment, text)
        # The standard library notice appears once, though both collections carry it.
        self.assertEqual(text.count('Rust standard library (rustc 1.90.0'), 1)
        self.assertNotIn('author@example.invalid', text)
        self.assertNotIn('typescript', text.lower())
        self.assertNotIn('## zeropw-desktop', text)
        self.assertNotIn(str(self.root), text)
        fetch = (self.root / 'cargo.log').read_text().splitlines()
        self.assertTrue(any('fetch --locked' in line and '--target ' + TARGET in line for line in fetch))

    def test_pretendard_notice_names_the_fonts_it_is_built_from(self):
        text = self.run_ok()
        section = text[text.index('## pretendard 1.3.9'):text.index('## react 19.0.0')]
        for fragment in ("with Reserved Font Name 'Pretendard'.", 'Copyright 2014-2021 Adobe (http://www.adobe.com/),',
                         "with Reserved Font Name 'Source'.",
                         'Copyright (c) 2016 The Inter Project Authors (https://github.com/rsms/inter),',
                         "with Reserved Font Name 'Inter'.",
                         'Copyright 2021 The M+ FONTS Project Authors (https://github.com/coz-m/MPLUS_FONTS),',
                         "with Reserved Font Name 'M PLUS 1'.", 'SIL OPEN FONT LICENSE Version 1.1',
                         'OTHER DEALINGS IN THE FONT SOFTWARE.', 'Synthetic OFL text', 'Reviewed: synthetic font review.',
                         '### Upstream notice (pretendard-LICENSE-0189074f.txt)'):
            self.assertIn(fragment, section)

    def test_font_without_a_reviewed_entry_or_with_a_stale_one_is_refused(self):
        self.output.parent.mkdir()
        self.output.write_text('stale notices from an earlier build')
        (self.desktop / 'node_modules/pretendard/dist/LICENSE.txt').unlink()
        self.assert_refused(self.run_tool(), 'pretendard 1.3.9: dist/LICENSE.txt is missing')
        self.lock['packages']['node_modules/pretendard']['version'] = '1.4.0'
        self.write_lock()
        (self.desktop / 'node_modules/pretendard/package.json').write_text(json.dumps({'name': 'pretendard', 'version': '1.4.0'}))
        self.assert_refused(self.run_tool(), 'pretendard 1.4.0: an OFL font needs a reviewed npm entry',
                            'supplement npm entry pretendard 1.3.9 matches no locked package')

    def test_reviewed_entry_must_list_every_notice_file(self):
        (self.desktop / 'node_modules/@fontsource/jetbrains-mono/NOTICE').write_text('Synthetic extra notice\n')
        self.assert_refused(self.run_tool(), '@fontsource/jetbrains-mono 5.3.0: notice files NOTICE are not in its reviewed entry')

    def test_build_tool_code_emitted_into_the_bundle_is_covered(self):
        text = self.run_ok()
        tools = text[text.index('## Build tools whose own code is emitted'):text.index('# 5. Source code')]
        for fragment in ('## rolldown 1.2.0', 'Emitted code: Synthetic runtime helper.', 'Synthetic Rolldown MIT notice',
                         '### THIRD-PARTY-LICENSE', 'Synthetic esbuild and Rollup notices',
                         '### Upstream notice (polyfill-origin.txt)', 'Copyright (C) Synthetic polyfill origin', '## vite 8.0.0',
                         'Emitted code: Synthetic preload polyfill.', 'Synthetic Vite MIT notice',
                         '### LICENSE.md (its first section, up to "# Licenses of bundled dependencies")'):
            self.assertIn(fragment, tools)
        self.assertNotIn('Synthetic bundled dependency notice', text)

    def test_build_tool_update_needs_a_new_review(self):
        self.lock['packages']['node_modules/vite']['version'] = '8.1.0'
        self.write_lock()
        (self.desktop / 'node_modules/vite/package.json').write_text(json.dumps({'name': 'vite', 'version': '8.1.0'}))
        self.assert_refused(self.run_tool(), 'vite 8.1.0: check which of its own code a source-mapped production build emits',
                            'supplement npm entry vite 8.0.0 matches no locked package')
        self.lock['packages']['node_modules/vite']['version'] = '8.0.0'
        self.write_lock()
        (self.desktop / 'node_modules/vite/package.json').write_text(json.dumps({'name': 'vite', 'version': '8.0.0'}))
        (self.desktop / 'node_modules/vite/LICENSE.md').write_text('Synthetic Vite notice without the reviewed heading\n')
        self.assert_refused(self.run_tool(), 'vite 8.0.0: LICENSE.md no longer starts with the reviewed section')

    def test_npm_package_without_notice_or_out_of_sync_install_is_refused(self):
        (self.desktop / 'node_modules/react/LICENSE').unlink()
        (self.desktop / 'node_modules/@fontsource/jetbrains-mono/package.json').write_text(
            json.dumps({'name': '@fontsource/jetbrains-mono', 'version': '5.2.0'}))
        self.assert_refused(self.run_tool(), 'react 19.0.0: no notice file', '@fontsource/jetbrains-mono 5.3.0: node_modules does not match')

    def test_symlinked_npm_notice_is_not_read(self):
        notice = self.desktop / 'node_modules/react/LICENSE'
        notice.unlink()
        outside = self.root / 'outside.txt'
        outside.write_text('do not read this content')
        notice.symlink_to(outside)
        self.assert_refused(self.run_tool(), 'react 19.0.0: no notice file')

    def test_sidecar_notices_must_be_the_static_openssl_build_for_the_target(self):
        text = self.sidecars.read_text()
        self.sidecars.write_text(text.replace('## OpenSSL 3.5.9 (statically linked release SDK)', '## Something else'))
        self.assert_refused(self.run_tool(), 'no statically linked OpenSSL notices')
        self.sidecars.write_text(text.replace('Target: ' + TARGET, 'Target: x86_64-apple-darwin'))
        self.assert_refused(self.run_tool(), 'not collected for ' + TARGET)
        self.sidecars.unlink()
        self.assert_refused(self.run_tool(), 'sidecar notices')

    def test_incomplete_or_stale_sidecar_notices_are_refused(self):
        text = self.sidecars.read_text()
        self.sidecars.write_text(text.replace('## openssl 0.10.0', '## ring 0.17.14\n\nDeclared license: ISC\n\n'
                                              'No root notice file found; manual review required.\n\n## openssl 0.10.0'))
        self.assert_refused(self.run_tool(), 'sidecar notices: incomplete')
        self.sidecars.write_text(re.sub(r'(?m)^Cargo\.lock SHA-256: .*\n', '', text))
        self.assert_refused(self.run_tool(), 'not collected from the current rust/Cargo.lock')
        self.sidecars.write_text(text)
        (self.rust / 'Cargo.lock').write_text('synthetic rust lockfile, updated after the sidecar build\n')
        self.assert_refused(self.run_tool(), 'not collected from the current rust/Cargo.lock')
        (self.rust / 'Cargo.lock').write_text('synthetic rust lockfile\n')
        self.collect_sidecars(rustc=fake_rust_toolchain(self.root, TARGET, release='1.91.0'))
        self.assert_refused(self.run_tool(), 'sidecar notices: collected with a different Rust toolchain')
        self.sidecars.write_text(text[:text.index('## Rust standard library')] + text[text.index('## OpenSSL 3.5.9'):])
        self.assert_refused(self.run_tool(), 'sidecar notices: no Rust standard library notice')

    def test_rust_crate_without_notice_is_refused(self):
        (self.root / 'registry/option-ext-0.2.0/LICENSE.md').unlink()
        self.assert_refused(self.run_tool(), 'option-ext 0.2.0')

    def test_supplement_covers_only_the_reviewed_version(self):
        self.supplement['packages'] = {'objc2 0.6.4': self.supplement['packages']['objc2 0.6.5']}
        self.write_supplement()
        self.assert_refused(self.run_tool(), 'objc2 0.6.5')


class RepositorySupplementTests(unittest.TestCase):
    """The reviewed notices committed in desktop/licenses match the locked desktop dependencies."""

    def setUp(self):
        self.supplement = json.loads((ROOT / 'desktop/licenses/supplement.json').read_text(encoding='utf-8'))

    def test_pretendard_upstream_notice_is_the_unchanged_upstream_file(self):
        self.assertEqual(hashlib.sha256(REVIEWED_PRETENDARD.read_bytes()).hexdigest(), PRETENDARD_UPSTREAM_SHA256)
        text = REVIEWED_PRETENDARD.read_text(encoding='utf-8')
        for holder, name in (('Kil Hyung-jin', 'Pretendard'), ('Adobe', 'Source'),
                             ('The Inter Project Authors', 'Inter'), ('The M+ FONTS Project Authors', 'M PLUS 1')):
            self.assertRegex(text, rf"Copyright[^\n]*{re.escape(holder)}[^\n]*,\nwith Reserved Font Name '{re.escape(name)}'\.")

    def test_every_font_and_build_tool_in_the_lockfile_is_reviewed_for_its_exact_version(self):
        lock = json.loads((ROOT / 'desktop/package-lock.json').read_text(encoding='utf-8'))['packages']
        locked = {(key.rsplit('node_modules/', 1)[-1], entry.get('version')): entry for key, entry in lock.items() if key}
        npm = self.supplement['npm']
        for (name, version), entry in locked.items():
            if not entry.get('dev') and 'OFL' in (entry.get('license') or ''):
                self.assertIn(f'{name} {version}', npm)
            if name in ('rolldown', 'vite'):
                self.assertTrue(npm.get(f'{name} {version}', {}).get('bundler_runtime'), name)
        for key in npm:
            self.assertIn(tuple(key.rsplit(' ', 1)), locked, key)
        self.assertEqual(npm['pretendard 1.3.9']['upstream_notice'], REVIEWED_PRETENDARD.name)

    def test_build_tool_upstream_notice_is_the_unchanged_upstream_file(self):
        # LICENSE at guybedford/es-module-shims 2d7ce60c2fe3ecbc73f3628fd16821d3285e9798, the origin of the
        # module-preload polyfill that Rolldown emits.
        shims = ROOT / 'desktop/licenses/es-module-shims-LICENSE-2d7ce60c.txt'
        self.assertEqual(hashlib.sha256(shims.read_bytes()).hexdigest(),
                         '13dc18f97f767475f7ad48fdd12a2e45be30fb309c604730f406f625cf7d8f7f')
        self.assertIn('Copyright (C) 2018-2021 Guy Bedford', shims.read_text(encoding='utf-8'))
        rolldown = [entry for key, entry in self.supplement['npm'].items() if key.startswith('rolldown ')]
        self.assertEqual([entry.get('upstream_notice') for entry in rolldown], [shims.name])

    def test_every_crate_entry_names_its_upstream_holders(self):
        lock = (ROOT / 'desktop/Cargo.lock').read_text(encoding='utf-8')
        locked = set(re.findall(r'^name = "([^"]+)"\nversion = "([^"]+)"', lock, re.M))
        for key, entry in self.supplement['packages'].items():
            with self.subTest(key=key):
                self.assertIn(tuple(key.split(' ')), locked)
                self.assertTrue(entry['source'].strip())
                if 'notices_from' in entry:
                    self.assertIn(tuple(entry['notices_from'].split(' ')), locked)
                    continue
                self.assertTrue(all(line.startswith('Copyright ') for line in entry['copyright']))
                if entry['standard_text'] != 'MPL-2.0':
                    self.assertTrue(entry['copyright'])
        # objc2, block2, objc2-encode and objc2-foundation still carry the code of the crates they were forked from.
        for key in ('objc2 0.6.5', 'block2 0.6.2', 'objc2-encode 4.1.0', 'objc2-foundation 0.3.2'):
            self.assertIn('Copyright (c) Steven Sheldon', self.supplement['packages'][key]['copyright'])


if __name__ == '__main__':
    unittest.main()
