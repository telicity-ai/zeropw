"""desktop/scripts/package-macos.py and the release Tauri config, with fake tools only.

Nothing here builds, signs or mounts anything: the packaging steps run against a fake runner
that imitates git, npm, the Tauri CLI, hdiutil, otool, lipo, codesign, plutil and spctl.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')
EXECUTABLES = ('zeropw-desktop',) + SIDECARS
DMG = 'zeropw-desktop-v0.1.0-aarch64-apple-darwin.dmg'


def load_packager():
    spec = importlib.util.spec_from_file_location('package_macos', ROOT / 'desktop/scripts/package-macos.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_tree(base, version='0.1.0', core_version=None):
    """The files package-macos.py reads from the source copy."""
    desktop = base / 'desktop'
    (desktop / 'src-tauri').mkdir(parents=True)
    (desktop / 'core').mkdir()
    (base / 'LICENSE').write_text('MIT License (synthetic)\n')
    (desktop / 'package.json').write_text(json.dumps({'name': 'zeropw-desktop', 'version': version}))
    (desktop / 'package-lock.json').write_text(json.dumps(
        {'name': 'zeropw-desktop', 'version': version, 'lockfileVersion': 3,
         'packages': {'': {'name': 'zeropw-desktop', 'version': version}}}))
    (desktop / 'src-tauri/tauri.conf.json').write_text(json.dumps({'productName': 'ZeroPW', 'version': version}))
    (desktop / 'src-tauri/tauri.bundle.conf.json').write_text(json.dumps({'bundle': {}}))
    (desktop / 'src-tauri/Cargo.toml').write_text(
        f'[package]\nname = "zeropw-desktop"\nversion = "{version}"\n\n[dependencies]\nserde = {{ version = "1" }}\n')
    (desktop / 'core/Cargo.toml').write_text(
        f'[package]\nname = "zeropw-desktop-core"\nversion = "{core_version or version}"\n')
    (desktop / 'Cargo.lock').write_text(
        f'version = 4\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n\n'
        f'[[package]]\nname = "zeropw-desktop"\nversion = "{version}"\n\n'
        f'[[package]]\nname = "zeropw-desktop-core"\nversion = "{core_version or version}"\n')


class FakeRunner:
    def __init__(self, test):
        self.test = test
        self.calls = []
        self.status = ''
        self.otool = {}
        self.codesign_verify = 0
        self.omit = set()
        self.attach_fails = False
        self.mounted = None

    def result(self, command, code=0, stdout='', stderr=''):
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    def run(self, command, cwd=None, env=None, check=True, capture=False):
        command = [str(part) for part in command]
        self.calls.append((command, cwd, env))
        tool = pathlib.Path(command[0]).name
        if tool == 'git':
            if 'status' in command:
                return self.result(command, stdout=self.status)
            if 'rev-parse' in command:
                return self.result(command, stdout='a' * 40 + '\n')
            pathlib.Path(command[command.index('-o') + 1]).write_bytes(b'synthetic archive')
            return self.result(command)
        if tool == 'tar':
            write_tree(pathlib.Path(command[command.index('-C') + 1]))
            return self.result(command)
        if tool in ('npm', 'sh'):
            if tool == 'sh':
                notices = pathlib.Path(cwd) / 'src-tauri/notices/THIRD_PARTY_LICENSES.md'
                notices.parent.mkdir(parents=True, exist_ok=True)
                notices.write_text('Synthetic third-party notices\n')
            return self.result(command)
        if tool == 'tauri':
            dmg = pathlib.Path(env['CARGO_TARGET_DIR']) / 'release/bundle/dmg/ZeroPW_0.1.0_aarch64.dmg'
            dmg.parent.mkdir(parents=True, exist_ok=True)
            dmg.write_bytes(b'synthetic disk image')
            return self.result(command)
        if tool == 'hdiutil':
            return self.hdiutil(command, cwd)
        relative = command[-1]
        name = pathlib.PurePosixPath(relative).name
        if tool == 'otool' and command[1] == '-L':
            return self.result(command, stdout=self.otool.get(name, f'{relative}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n'))
        if tool == 'otool':
            return self.result(command, stdout='Load command 9\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform 1\n    minos 11.0\n      sdk 26.0\n')
        if tool == 'lipo':
            return self.result(command, stdout='arm64\n')
        if tool == 'codesign' and '--verify' in command:
            return self.result(command, self.codesign_verify, stderr=f'{relative}: valid on disk\n')
        if tool == 'codesign':
            text = (f'Executable={cwd}/{relative}\nCodeDirectory v=20500 size=100 flags=0x10002(adhoc,runtime) hashes=1+7 location=embedded\n'
                    'Signature=adhoc\n')
            if relative.endswith('.app'):
                text += 'Sealed Resources version=2 rules=13 files=4\n'
            return self.result(command, stderr=text)
        if tool == 'plutil':
            values = {'CFBundleShortVersionString': '0.1.0', 'LSMinimumSystemVersion': '11.0',
                      'NSLocalNetworkUsageDescription': 'synthetic description'}
            return self.result(command, stdout=values[command[2]] + '\n')
        if tool == 'spctl':
            return self.result(command, 3, stderr=f'{relative}: rejected\nsource=no usable signature\n')
        raise AssertionError('unexpected command ' + ' '.join(command))

    def hdiutil(self, command, cwd):
        if command[1] == 'verify':
            return self.result(command, stdout=f'hdiutil: verify: checksum of "{command[2]}" is VALID\n')
        if command[1] == 'attach':
            self.test.assertIn('-readonly', command)
            if self.attach_fails:
                return self.result(command, 1, stderr='hdiutil: attach failed - synthetic\n')
            # hdiutil chooses the mount point; here a folder inside the test's directory.
            work = pathlib.Path(cwd).parent
            mount = work.parent / 'Volumes/ZeroPW'
            contents = mount / 'ZeroPW.app/Contents'
            (contents / 'MacOS').mkdir(parents=True)
            (contents / 'Resources').mkdir()
            for name in EXECUTABLES:
                if name not in self.omit:
                    (contents / 'MacOS' / name).write_bytes(b'synthetic executable')
            shutil.copyfile(work / 'source/LICENSE', contents / 'Resources/LICENSE')
            if 'THIRD_PARTY_LICENSES.md' not in self.omit:
                shutil.copyfile(work / 'source/desktop/src-tauri/notices/THIRD_PARTY_LICENSES.md',
                                contents / 'Resources/THIRD_PARTY_LICENSES.md')
            (contents / 'Info.plist').write_text('synthetic plist')
            (mount / 'Applications').symlink_to('/Applications')
            self.mounted = mount
            entities = [{'dev-entry': '/dev/disk9s1', 'mount-point': str(mount)}, {'dev-entry': '/dev/disk9'}]
            return self.result(command, stdout=plistlib.dumps({'system-entities': entities}).decode())
        if command[1] == 'detach':
            mount = pathlib.Path(command[2])
            shutil.rmtree(mount, ignore_errors=True)
            self.mounted = None
            return self.result(command)
        raise AssertionError('unexpected hdiutil command')


class PackageMacosTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = pathlib.Path(temp.name)
        self.work, self.out = self.base / 'work', self.base / 'out'
        self.module = load_packager()
        self.runner = FakeRunner(self)
        self.environ = {'PATH': '/usr/bin:/bin', 'HOME': str(self.base / 'home')}

    def package(self, environ=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.module.main(['--work-dir', str(self.work), '--out-dir', str(self.out)],
                                    environ=self.environ if environ is None else environ,
                                    runner=self.runner, system=('Darwin', 'arm64'))

    def tools(self):
        return [pathlib.Path(command[0]).name + (' ' + command[1] if pathlib.Path(command[0]).name in ('hdiutil', 'codesign') else '')
                for command, _, _ in self.runner.calls]

    def test_credentials_in_the_environment_stop_everything(self):
        for name in ('APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID',
                     'APPLE_PASSWORD', 'APPLE_TEAM_ID', 'APPLE_API_KEY', 'APPLE_API_ISSUER', 'APPLE_API_KEY_PATH',
                     'TAURI_SIGNING_PRIVATE_KEY', 'NOTARYTOOL_PROFILE', 'AC_PASSWORD', 'apple_id'):
            with self.subTest(name=name):
                with self.assertRaises(SystemExit) as raised:
                    self.package(dict(self.environ, **{name: 'synthetic-credential-value'}))
                self.assertIn(name, str(raised.exception))
                self.assertNotIn('synthetic-credential-value', str(raised.exception))
        self.assertEqual(self.runner.calls, [])
        self.assertFalse(self.work.exists())

    def test_build_environment_carries_no_credentials(self):
        environment = self.module.build_environment(
            {'PATH': '/usr/bin', 'APPLE_ID': 'x', 'TAURI_BUNDLER_DMG_IGNORE_CI': 'true', 'CI': 'false'}, '/t')
        self.assertEqual(environment, {'PATH': '/usr/bin', 'CI': 'true', 'MACOSX_DEPLOYMENT_TARGET': '11.0',
                                       'CARGO_TARGET_DIR': '/t'})

    def test_disagreeing_versions_are_named_before_building(self):
        tree = self.base / 'tree'
        write_tree(tree, core_version='0.2.0')
        with self.assertRaises(SystemExit) as raised:
            self.module.release_version(tree)
        self.assertIn('desktop/core/Cargo.toml [package] version: 0.2.0', str(raised.exception))
        self.assertIn('desktop/Cargo.lock zeropw-desktop-core: 0.2.0', str(raised.exception))
        other = self.base / 'other'
        write_tree(other)
        self.assertEqual(self.module.release_version(other), 'v0.1.0')
        tauri = other / 'desktop/src-tauri/tauri.conf.json'
        tauri.write_text(json.dumps({'version': '0.1.0-beta'}))
        with self.assertRaises(SystemExit):
            self.module.release_version(other)

    def test_package_builds_from_head_and_ships_only_verified_artifacts(self):
        self.assertEqual(self.package(), 0)
        tools = self.tools()
        order = ['git', 'tar', 'npm', 'sh', 'tauri', 'hdiutil verify', 'hdiutil attach', 'codesign --verify',
                 'spctl', 'hdiutil detach']
        positions = [tools.index(step) for step in order]
        self.assertEqual(positions, sorted(positions), tools)
        tauri_command, tauri_cwd, environment = next(c for c in self.runner.calls if pathlib.Path(c[0][0]).name == 'tauri')
        self.assertEqual(tauri_command[1:], ['build', '--config', 'src-tauri/tauri.bundle.conf.json', '--bundles', 'app,dmg'])
        self.assertEqual(environment['CI'], 'true')
        self.assertEqual(environment['MACOSX_DEPLOYMENT_TARGET'], '11.0')
        self.assertFalse(any(key.startswith('APPLE_') for key in environment))
        self.assertEqual(pathlib.Path(tauri_cwd), self.work.resolve() / 'source/desktop')
        npm = next(c for c, _, _ in self.runner.calls if c[0] == 'npm')
        self.assertIn('--ignore-scripts', npm)
        sidecars = next(c for c, _, _ in self.runner.calls if c[0] == 'sh')
        self.assertEqual(sidecars[1:], ['scripts/prepare-sidecars.sh', 'aarch64-apple-darwin'])
        for name in ('otool', 'lipo'):
            checked = {pathlib.PurePosixPath(c[-1]).name for c, _, _ in self.runner.calls if c[0] == name}
            self.assertEqual(checked, set(EXECUTABLES))

        produced = sorted(path.name for path in self.out.iterdir())
        self.assertEqual(produced, sorted([DMG, DMG + '.sha256', 'zeropw-desktop-v0.1.0-aarch64-apple-darwin-THIRD_PARTY_LICENSES.md',
                                           'zeropw-desktop-v0.1.0-aarch64-apple-darwin-verification.txt']))
        digest = hashlib.sha256(b'synthetic disk image').hexdigest()
        self.assertEqual((self.out / (DMG + '.sha256')).read_text(), f'{digest}  {DMG}\n')
        log = (self.out / 'zeropw-desktop-v0.1.0-aarch64-apple-darwin-verification.txt').read_text()
        self.assertIn('source commit: ' + 'a' * 40, log)
        self.assertIn('ZeroPW.app: rejected', log)
        self.assertIn('spctl result: rejected (exit 3)', log)
        self.assertTrue(log.rstrip().endswith('RESULT: PASS'))
        self.assertIn('Executable=<mount>/ZeroPW.app/Contents/MacOS/zeropw-admin', log)
        self.assertNotIn(str(self.base), log)
        self.assertIsNone(self.runner.mounted)

    def test_homebrew_openssl_in_any_executable_fails_and_ships_nothing(self):
        self.runner.otool['zeropw-admin'] = ('ZeroPW.app/Contents/MacOS/zeropw-admin:\n'
                                             '\t/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n')
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('zeropw-admin links /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib', str(raised.exception))
        self.assertFalse(self.out.exists())
        self.assertEqual(self.tools()[-1], 'hdiutil detach')
        self.assertIsNone(self.runner.mounted)

    def test_failed_signature_check_or_missing_notice_fails(self):
        self.runner.codesign_verify = 1
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('codesign --verify --deep --strict failed', str(raised.exception))
        self.runner = FakeRunner(self)
        self.runner.omit = {'THIRD_PARTY_LICENSES.md', 'zeropw_session'}
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('Resources/THIRD_PARTY_LICENSES.md is missing', str(raised.exception))
        self.assertIn('MacOS/zeropw_session is missing', str(raised.exception))
        self.assertFalse(self.out.exists())

    def test_image_that_does_not_mount_fails_with_its_record(self):
        self.runner.attach_fails = True
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('hdiutil attach failed', str(raised.exception))
        log = (self.work / 'artifacts/zeropw-desktop-v0.1.0-aarch64-apple-darwin-verification.txt').read_text()
        self.assertIn('hdiutil: attach failed - synthetic', log)
        self.assertTrue(log.rstrip().endswith('RESULT: FAIL'))
        self.assertFalse(self.out.exists())

    def test_existing_artifacts_and_dirty_trees_are_refused(self):
        self.runner.status = ' M desktop/package.json\n'
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('tracked changes', str(raised.exception))
        self.assertNotIn('tar', self.tools())
        self.runner = FakeRunner(self)
        self.out.mkdir()
        (self.out / DMG).write_bytes(b'already published')
        with self.assertRaises(SystemExit) as raised:
            self.package()
        self.assertIn('refusing to replace ' + DMG, str(raised.exception))
        self.assertNotIn('npm', self.tools())
        self.assertEqual((self.out / DMG).read_bytes(), b'already published')

    def test_directories_inside_the_checkout_are_refused(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()):
                self.module.main(['--work-dir', str(ROOT / 'desktop/target/package'), '--out-dir', str(self.out)],
                                 environ=self.environ, runner=self.runner, system=('Darwin', 'arm64'))
        self.assertEqual(self.runner.calls, [])

    def test_linkage_filter(self):
        output = ('x:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n'
                  '\t/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit (compatibility version 1.0.0)\n')
        self.assertEqual(self.module.linkage_problems(output), [])
        for bad in ('/usr/local/lib/libfoo.dylib', '/opt/homebrew/lib/libz.dylib', '/usr/lib/libssl.48.dylib',
                    '@rpath/libcrypto.3.dylib'):
            self.assertEqual(self.module.linkage_problems(f'x:\n\t{bad} (compatibility version 1.0.0)\n'), [bad + ' (compatibility version 1.0.0)'])


class ReleaseConfigCheckTests(unittest.TestCase):
    """desktop/scripts/check-tauri.mjs against a copy of the desktop sources with one change each."""

    def setUp(self):
        if not shutil.which('node'):
            self.fail('the release config check requires Node.js')
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.copy = pathlib.Path(temp.name)
        ignore = shutil.ignore_patterns('node_modules', 'dist', 'target', 'gen', 'icons', 'binaries', 'notices',
                                        '.DS_Store', '__pycache__')
        shutil.copytree(ROOT / 'desktop', self.copy / 'desktop', ignore=ignore)
        (self.copy / 'docs').mkdir()
        shutil.copyfile(ROOT / 'docs/desktop-app.md', self.copy / 'docs/desktop-app.md')
        self.tauri = self.copy / 'desktop/src-tauri'

    def check(self):
        return subprocess.run(['node', str(self.copy / 'desktop/scripts/check-tauri.mjs')], capture_output=True, text=True)

    def edit(self, name, change):
        path = self.tauri / name
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def test_the_committed_configs_pass(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signing_identity_is_ad_hoc_or_absent(self):
        self.edit('tauri.bundle.conf.json', lambda c: c['bundle']['macOS'].pop('signingIdentity'))
        self.assertEqual(self.check().returncode, 0)
        self.edit('tauri.bundle.conf.json', lambda c: c['bundle']['macOS'].update(signingIdentity='Developer ID Application: Example (ABCDE12345)'))
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('signingIdentity must be "-"', result.stderr)

    def test_release_only_and_credential_settings_are_refused(self):
        cases = [
            ('tauri.bundle.conf.json', lambda c: c['bundle']['macOS'].update(providerShortName='EXAMPLE'), 'providerShortName'),
            ('tauri.bundle.conf.json', lambda c: c['bundle']['macOS'].update(entitlements='Entitlements.plist'), 'entitlements'),
            ('tauri.bundle.conf.json', lambda c: c['bundle']['macOS'].update(minimumSystemVersion='10.13'), 'minimumSystemVersion'),
            ('tauri.bundle.conf.json', lambda c: c['bundle'].update(createUpdaterArtifacts=True), 'exactly externalBin'),
            ('tauri.bundle.conf.json', lambda c: c['bundle']['resources'].update({'../../README.md': 'README.md'}), 'bundle.resources'),
            ('tauri.bundle.conf.json', lambda c: c.update(identifier='example'), 'only a bundle section'),
            ('tauri.conf.json', lambda c: c['bundle'].update(macOS={'signingIdentity': '-'}), 'release-only'),
            ('tauri.conf.json', lambda c: c['bundle'].update(resources=['../../LICENSE']), 'release-only'),
            ('tauri.conf.json', lambda c: c['bundle'].update(windows={'certificateThumbprint': 'ABC'}), 'certificateThumbprint'),
        ]
        for name, change, message in cases:
            with self.subTest(message=message):
                original = (self.tauri / name).read_text()
                self.edit(name, change)
                result = self.check()
                (self.tauri / name).write_text(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_info_plist_holds_only_the_local_network_description(self):
        plist = self.tauri / 'Info.release.plist'
        original = plist.read_text()
        plist.write_text(original.replace('</dict>', '  <key>NSAppTransportSecurity</key>\n  <dict/>\n</dict>'))
        self.assertIn('must hold only NSLocalNetworkUsageDescription', self.check().stderr)
        plist.write_text(original)
        (self.tauri / 'Info.plist').write_text(original)
        self.assertIn('Info.plist would be merged into every build', self.check().stderr)


if __name__ == '__main__':
    unittest.main()
