"""desktop/scripts/third-party-licenses.py with synthetic Cargo metadata, lockfile and node_modules."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'desktop/scripts/third-party-licenses.py'
TARGET = 'aarch64-apple-darwin'


class DesktopLicenseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.desktop = self.root / 'desktop'
        self.desktop.mkdir()
        (self.desktop / 'Cargo.toml').write_text('synthetic workspace manifest')
        packages = []
        for name, version, license_name, notice in (('zeropw-desktop', '0.1.0', 'MIT', None),
                                                    ('tauri', '2.0.0', 'Apache-2.0 OR MIT', 'LICENSE-MIT'),
                                                    ('option-ext', '0.2.0', 'MPL-2.0', 'LICENSE.md'),
                                                    ('objc2', '0.6.5', 'MIT', None)):
            crate = self.root / 'registry' / name
            crate.mkdir(parents=True)
            (crate / 'Cargo.toml').write_text('synthetic crate manifest')
            if notice:
                (crate / notice).write_text(f'Synthetic upstream notice for {name}\n')
            packages.append({'id': name, 'name': name, 'version': version, 'license': license_name,
                             'license_file': None, 'manifest_path': str(crate / 'Cargo.toml'),
                             'authors': ['Synthetic Author <author@example.invalid>'],
                             'repository': 'https://example.invalid/' + name})
        metadata = {'workspace_members': ['zeropw-desktop'], 'packages': packages, 'resolve': {'nodes': [
            {'id': 'zeropw-desktop', 'deps': [{'pkg': 'tauri', 'dep_kinds': [{'kind': None}]}]},
            {'id': 'tauri', 'deps': [{'pkg': 'option-ext', 'dep_kinds': [{'kind': None}]},
                                     {'pkg': 'objc2', 'dep_kinds': [{'kind': None}]}]},
            {'id': 'option-ext', 'deps': []}, {'id': 'objc2', 'deps': []}]}}
        # objc2 publishes no notice file; the reviewed supplement supplies the standard MIT text.
        (self.desktop / 'licenses').mkdir()
        (self.desktop / 'licenses/MIT.txt').write_text('Synthetic standard MIT text\n')
        (self.desktop / 'licenses/supplement.json').write_text(json.dumps(
            {'packages': {'objc2 0.6.5': {'license': 'MIT', 'standard_text': 'MIT'}}}))
        (self.root / 'metadata.json').write_text(json.dumps(metadata))
        tools = self.root / 'tools'
        tools.mkdir()
        (tools / 'cargo').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(self.root / 'cargo.log') + '"\n'
                                     'if [ "$1" = fetch ]; then exit 0; fi\n'
                                     'cat "' + str(self.root / 'metadata.json') + '"\n')
        (tools / 'cargo').chmod(0o755)
        self.environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ.get('PATH', os.defpath))
        lock = {'name': 'zeropw-desktop', 'version': '0.1.0', 'lockfileVersion': 3, 'packages': {
            '': {'name': 'zeropw-desktop', 'version': '0.1.0'},
            'node_modules/react': {'version': '19.0.0', 'license': 'MIT'},
            'node_modules/pretendard': {'version': '1.3.9', 'license': 'OFL-1.1'},
            'node_modules/@fontsource/jetbrains-mono': {'version': '5.3.0', 'license': 'OFL-1.1'},
            'node_modules/vite': {'version': '8.0.0', 'license': 'MIT', 'dev': True}}}
        (self.desktop / 'package-lock.json').write_text(json.dumps(lock))
        for key, entry in lock['packages'].items():
            if not key:
                continue
            directory = self.desktop / key
            directory.mkdir(parents=True)
            name = key.split('node_modules/', 1)[1]
            (directory / 'package.json').write_text(json.dumps({'name': name, 'version': entry['version']}))
        (self.desktop / 'node_modules/react/LICENSE').write_text('Synthetic React MIT notice\n')
        (self.desktop / 'node_modules/@fontsource/jetbrains-mono/LICENSE').write_text('Synthetic JetBrains Mono OFL notice\n')
        (self.desktop / 'node_modules/pretendard/dist').mkdir()
        (self.desktop / 'node_modules/pretendard/dist/LICENSE.txt').write_text('Synthetic Pretendard OFL notice\n')
        self.sidecars = self.root / 'sidecars.md'
        self.sidecars.write_text('# Third-party dependency licenses\n\nTarget: aarch64-apple-darwin. Build/runtime closure.\n\n'
                                 '## openssl 0.10.0\n\nDeclared license: Apache-2.0\n\n### LICENSE\n\n    Synthetic openssl crate notice\n'
                                 '## OpenSSL 3.5.9 (statically linked release SDK)\n\n### LICENSE.txt\n\n    Synthetic OpenSSL notice\n')
        self.output = self.root / 'out/THIRD_PARTY_LICENSES.md'

    def run_tool(self):
        return subprocess.run([sys.executable, str(SCRIPT), '--target', TARGET, '--sidecar-notices', str(self.sidecars),
                               '--output', str(self.output), '--desktop-dir', str(self.desktop)],
                              env=self.environment, capture_output=True, text=True)

    def assert_refused(self, result, *fragments):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)

    def test_all_three_groups_and_mpl_sources_are_collected(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.output.read_text()
        for fragment in ('# 1. App executable: Rust crates', '### tauri 2.0.0', 'Synthetic upstream notice for tauri',
                         '# 2. Bundled command-line binaries and OpenSSL', '### OpenSSL 3.5.9 (statically linked release SDK)',
                         'Synthetic OpenSSL notice', '# 3. Web interface: npm packages', '## pretendard 1.3.9',
                         'Declared license: OFL-1.1', 'Synthetic Pretendard OFL notice', '### dist/LICENSE.txt',
                         'Synthetic JetBrains Mono OFL notice', 'Synthetic React MIT notice', '3 npm packages',
                         '- option-ext 0.2.0: https://crates.io/crates/option-ext/0.2.0',
                         '### objc2 0.6.5', 'Synthetic standard MIT text',
                         'Copyright holders declared in the package metadata: Synthetic Author.'):
            self.assertIn(fragment, text)
        self.assertNotIn('author@example.invalid', text)
        self.assertNotIn('vite', text)
        self.assertNotIn('## zeropw-desktop', text)
        self.assertNotIn(str(self.root), text)
        fetch = (self.root / 'cargo.log').read_text().splitlines()[0]
        self.assertIn('fetch --locked', fetch)
        self.assertIn('--target ' + TARGET, fetch)

    def test_font_notice_outside_the_package_root_is_required(self):
        self.output.parent.mkdir()
        self.output.write_text('stale notices from an earlier build')
        (self.desktop / 'node_modules/pretendard/dist/LICENSE.txt').unlink()
        self.assert_refused(self.run_tool(), 'pretendard 1.3.9: dist/LICENSE.txt is missing')

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
        self.sidecars.write_text(text.replace(TARGET, 'x86_64-apple-darwin'))
        self.assert_refused(self.run_tool(), 'not collected for ' + TARGET)
        self.sidecars.unlink()
        self.assert_refused(self.run_tool(), 'sidecar notices')

    def test_rust_crate_without_notice_is_refused(self):
        (self.root / 'registry/option-ext/LICENSE.md').unlink()
        self.assert_refused(self.run_tool(), 'option-ext 0.2.0')

    def test_supplement_covers_only_the_reviewed_version(self):
        (self.desktop / 'licenses/supplement.json').write_text(json.dumps(
            {'packages': {'objc2 0.6.4': {'license': 'MIT', 'standard_text': 'MIT'}}}))
        self.assert_refused(self.run_tool(), 'objc2 0.6.5')


if __name__ == '__main__':
    unittest.main()
