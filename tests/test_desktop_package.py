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
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = 'aarch64-apple-darwin'
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')
EXECUTABLES = ('zeropw-desktop',) + SIDECARS
BASE = 'zeropw-desktop-v0.1.0-aarch64-apple-darwin'
DMG = BASE + '.dmg'
LOG = BASE + '-verification.txt'
SET_BY_PACKAGER = {'CI', 'MACOSX_DEPLOYMENT_TARGET', 'CARGO_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS', 'CFLAGS'}


def load_packager():
    spec = importlib.util.spec_from_file_location('package_macos', ROOT / 'desktop/scripts/package-macos.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def macho(payload, linkedit_vmsize=0x4000, uuid=b'\x11' * 16, signed=False):
    """A minimal thin arm64 Mach-O: header, LC_SEGMENT_64 __LINKEDIT, LC_UUID[, LC_CODE_SIGNATURE]."""
    commands = struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', 0x100000000, linkedit_vmsize, 4096,
                           len(payload), 1, 1, 0, 0)
    commands += struct.pack('<II16s', 0x1b, 24, uuid)
    count = 2
    if signed:
        commands += struct.pack('<IIII', 0x1d, 16, 4096, 0)
        count += 1
    return struct.pack('<IIIIIIII', 0xfeedfacf, 0x0100000c, 0, 2, count, len(commands), 0, 0) + commands + payload


def resign(data):
    """What Tauri's codesign does to the bytes the comparison sees: a larger __LINKEDIT vmsize."""
    data = bytearray(data)
    data[32 + 32:32 + 40] = struct.pack('<Q', 0x8000)
    return bytes(data)


def write_tree(base, version='0.1.0', core_version=None, product_version=None):
    """The files package-macos.py reads from the source copy."""
    desktop = base / 'desktop'
    (desktop / 'src-tauri').mkdir(parents=True)
    (desktop / 'core').mkdir()
    (base / 'rust').mkdir()
    (base / 'LICENSE').write_text('MIT License (synthetic)\n')
    (base / 'rust/Cargo.toml').write_text(
        f'[package]\nname = "zeropw"\nversion = "{product_version or version}"\n\n[dependencies]\nserde = "1"\n')
    (base / 'rust/Cargo.lock').write_text(
        f'version = 4\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n\n'
        f'[[package]]\nname = "zeropw"\nversion = "{product_version or version}"\n')
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
        self.detach_fails = False
        self.mounted = None
        self.tree = {}            # write_tree keyword arguments
        self.shipped = {}         # executable name -> bytes in the image instead of the re-signed build
        self.entitlements = {}    # executable or bundle name -> codesign --entitlements output
        self.bundled_differs = False
        self.during_tauri = None  # called while "tauri build" runs
        self.private = set()      # Resources file names the image ships with mode 0600
        self.target = None

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
            write_tree(pathlib.Path(command[command.index('-C') + 1]), **self.tree)
            return self.result(command)
        if tool == 'npm':
            return self.result(command)
        if tool == 'sh':
            return self.prepare_sidecars(command, pathlib.Path(cwd), env)
        if tool == 'tauri':
            target = self.target = pathlib.Path(env['CARGO_TARGET_DIR'])
            dmg = target / 'release/bundle/dmg/ZeroPW_0.1.0_aarch64.dmg'
            dmg.parent.mkdir(parents=True, exist_ok=True)
            dmg.write_bytes(b'synthetic disk image')
            (target / 'release/zeropw-desktop').write_bytes(macho(b'synthetic app executable', uuid=b'\x22' * 16))
            if self.during_tauri:
                self.during_tauri()
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
        if tool == 'codesign' and '--remove-signature' in command:
            # The synthetic executables carry no LC_CODE_SIGNATURE; removal leaves them as they are.
            self.test.assertTrue((pathlib.Path(cwd) / relative).is_file())
            return self.result(command)
        if tool == 'codesign' and '--entitlements' in command:
            return self.result(command, stdout=self.entitlements.get(name, ''), stderr=f'Executable={cwd}/{relative}\n')
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

    def prepare_sidecars(self, command, desktop, env):
        self.test.assertEqual(command[1:], ['scripts/prepare-sidecars.sh', TARGET])
        notices = desktop / 'src-tauri/notices/THIRD_PARTY_LICENSES.md'
        notices.parent.mkdir(parents=True, exist_ok=True)
        notices.write_text('Synthetic third-party notices\n')
        built = pathlib.Path(env['CARGO_TARGET_DIR']) / f'sidecars-{TARGET}/bin'
        built.mkdir(parents=True, exist_ok=True)
        (desktop / 'src-tauri/binaries').mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(SIDECARS):
            data = macho(b'synthetic sidecar ' + name.encode(), uuid=bytes([0x30 + index]) * 16)
            (built / name).write_bytes(data)
            bundled = data + (b'!' if self.bundled_differs else b'')
            (desktop / 'src-tauri/binaries' / f'{name}-{TARGET}').write_bytes(bundled)
        return self.result(command)

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
            origins = {'zeropw-desktop': self.target / 'release/zeropw-desktop'}
            origins.update({name: work / f'source/desktop/src-tauri/binaries/{name}-{TARGET}' for name in SIDECARS})
            for name in EXECUTABLES:
                if name not in self.omit:
                    data = self.shipped.get(name) or resign(origins[name].read_bytes())
                    (contents / 'MacOS' / name).write_bytes(data)
            shutil.copyfile(work / 'source/LICENSE', contents / 'Resources/LICENSE')
            if 'THIRD_PARTY_LICENSES.md' not in self.omit:
                shutil.copyfile(work / 'source/desktop/src-tauri/notices/THIRD_PARTY_LICENSES.md',
                                contents / 'Resources/THIRD_PARTY_LICENSES.md')
            for name in self.private:
                os.chmod(contents / 'Resources' / name, 0o600)
            (contents / 'Info.plist').write_text('synthetic plist')
            (mount / 'Applications').symlink_to('/Applications')
            self.mounted = mount
            entities = [{'dev-entry': '/dev/disk9s1', 'mount-point': str(mount)}, {'dev-entry': '/dev/disk9'}]
            return self.result(command, stdout=plistlib.dumps({'system-entities': entities}).decode())
        if command[1] == 'detach':
            if self.detach_fails:
                return self.result(command, 16, stderr='hdiutil: detach failed - Resource busy\n')
            mount = pathlib.Path(command[2])
            shutil.rmtree(mount, ignore_errors=True)
            self.mounted = None
            return self.result(command)
        raise AssertionError('unexpected hdiutil command')


class PackageMacosTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = pathlib.Path(temp.name).resolve()
        self.work, self.out = self.base / 'work', self.base / 'out'
        self.module = load_packager()
        self.runner = FakeRunner(self)
        self.environ = {'PATH': '/usr/bin:/bin', 'HOME': str(self.base / 'home'), 'LANG': 'en_US.UTF-8',
                        'LC_CTYPE': 'UTF-8', 'TERM': 'xterm-256color',
                        # Not credentials, but not on the allowlist either: none reaches the build.
                        'RUSTFLAGS': '-C target-cpu=native', 'CARGO_ENCODED_RUSTFLAGS': '-Lnative=/opt/local/lib',
                        'CC': '/opt/local/bin/clang', 'LIBRARY_PATH': '/opt/local/lib', 'NODE_OPTIONS': '--require x',
                        'OPENSSL_DIR': '/opt/homebrew/opt/openssl@3', 'DYLD_LIBRARY_PATH': '/opt/local/lib',
                        'TAURI_CONFIG': '{}', 'TAURI_BUNDLER_DMG_IGNORE_CI': 'true', 'CI': 'false'}

    def package(self, environ=None, extra=()):
        extra = list(extra) if '--tag' in extra else [*extra, '--tag', 'v0.1.0']
        with contextlib.redirect_stdout(io.StringIO()):
            return self.module.main(['--work-dir', str(self.work), '--out-dir', str(self.out), *extra],
                                    environ=self.environ if environ is None else environ,
                                    runner=self.runner, system=('Darwin', 'arm64'))

    def failure(self, environ=None, extra=()):
        with self.assertRaises(SystemExit) as raised:
            self.package(environ, extra)
        return str(raised.exception)

    def tools(self):
        return [pathlib.Path(command[0]).name + (' ' + command[1] if pathlib.Path(command[0]).name in ('hdiutil', 'codesign') else '')
                for command, _, _ in self.runner.calls]

    def log(self):
        for directory in (self.out, self.work / 'artifacts'):
            if (directory / LOG).is_file():
                return (directory / LOG).read_text()
        self.fail('no verification log')

    def test_credential_like_variables_stop_everything_and_only_names_are_shown(self):
        for name in ('APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID',
                     'APPLE_PASSWORD', 'APPLE_TEAM_ID', 'APPLE_API_KEY', 'APPLE_API_ISSUER', 'APPLE_API_KEY_PATH',
                     'TAURI_SIGNING_PRIVATE_KEY', 'NOTARYTOOL_PROFILE', 'AC_PASSWORD', 'apple_id',
                     'ZEROPW_CALLER_TOKEN', 'ZEROPW_ADMIN_PASSPHRASE', 'zeropw_recovery_passphrase', 'ZEROPW_BIN_DIR',
                     'GH_TOKEN', 'GITHUB_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'CARGO_REGISTRY_TOKEN',
                     'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'CLAUDE_CODE_MESSAGING_TOKEN', 'AWS_SECRET_ACCESS_KEY',
                     'SSH_AUTH_SOCK', 'CSC_LINK', 'CSC_KEY_PASSWORD', 'P12_PASSWORD', 'DEVELOPER_ID_PASSWORD',
                     'client_secret', 'Signing_Passphrase'):
            with self.subTest(name=name):
                message = self.failure(dict(self.environ, **{name: 'synthetic-credential-value'}))
                self.assertIn(name, message)
                self.assertNotIn('synthetic-credential-value', message)
        message = self.failure(dict(self.environ, GH_TOKEN='synthetic-1', ZEROPW_CALLER_TOKEN='synthetic-2'))
        self.assertIn('GH_TOKEN, ZEROPW_CALLER_TOKEN', message)
        self.assertNotIn('synthetic-', message)
        self.assertEqual(self.runner.calls, [])
        self.assertFalse(self.work.exists())

    def test_build_environment_is_the_allowlist_plus_what_the_packager_sets(self):
        environment = self.module.build_environment(
            dict(self.environ, SHELL='/bin/zsh', USER='builder', LC_ALL='C', DEVELOPER_DIR='/Library/Developer/CommandLineTools'),
            '/t')
        self.assertEqual(environment, {'PATH': '/usr/bin:/bin', 'HOME': str(self.base / 'home'), 'LANG': 'en_US.UTF-8',
                                       'LC_CTYPE': 'UTF-8', 'LC_ALL': 'C', 'TERM': 'xterm-256color', 'SHELL': '/bin/zsh',
                                       'USER': 'builder', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools',
                                       'CI': 'true', 'MACOSX_DEPLOYMENT_TARGET': '11.0', 'CARGO_TARGET_DIR': '/t'})

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

    def test_the_product_version_must_match_the_desktop_version(self):
        # rust/Cargo.toml bumped for the release but the desktop fields not, and the reverse.
        for tree in ({'product_version': '0.2.0'}, {'version': '0.2.0', 'product_version': '0.1.0'}):
            with self.subTest(tree=tree):
                self.runner = FakeRunner(self)
                self.runner.tree = tree
                message = self.failure()
                self.assertIn('rust/Cargo.toml [package] version: ' + (tree['product_version']), message)
                self.assertIn('rust/Cargo.lock zeropw: ' + tree['product_version'], message)
                self.assertNotIn('npm', self.tools())
        self.assertFalse(self.out.exists())

    def test_tag_must_name_the_release_version(self):
        message = self.failure(extra=['--tag', 'v0.2.0'])
        self.assertIn('--tag v0.2.0 does not match the release version v0.1.0', message)
        self.assertNotIn('npm', self.tools())
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stderr(io.StringIO()):
                self.package(extra=['--tag', '0.1.0'])
        self.assertEqual(raised.exception.code, 2)
        self.runner = FakeRunner(self)
        self.assertEqual(self.package(extra=['--tag', 'v0.1.0']), 0)
        self.assertIn('release tag: v0.1.0 (matches)', (self.out / LOG).read_text())

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
        self.assertEqual(pathlib.Path(tauri_cwd), self.work / 'source/desktop')
        npm = next(c for c, _, _ in self.runner.calls if c[0] == 'npm')
        self.assertIn('--ignore-scripts', npm)
        for name in ('otool', 'lipo'):
            checked = {pathlib.PurePosixPath(c[-1]).name for c, _, _ in self.runner.calls if c[0] == name}
            self.assertEqual(checked, set(EXECUTABLES))
        entitlements = {pathlib.PurePosixPath(c[-1]).name for c, _, _ in self.runner.calls
                        if c[0] == 'codesign' and '--entitlements' in c}
        self.assertEqual(entitlements, set(EXECUTABLES) | {'ZeroPW.app'})

        produced = sorted(path.name for path in self.out.iterdir())
        self.assertEqual(produced, sorted([DMG, DMG + '.sha256', BASE + '-THIRD_PARTY_LICENSES.md', LOG]))
        digest = hashlib.sha256(b'synthetic disk image').hexdigest()
        self.assertEqual((self.out / (DMG + '.sha256')).read_text(), f'{digest}  {DMG}\n')
        log = (self.out / LOG).read_text()
        self.assertIn('source commit: ' + 'a' * 40, log)
        self.assertIn('product version: v0.1.0', log)
        self.assertIn('release tag: v0.1.0 (matches)', log)
        self.assertIn('ZeroPW.app: rejected', log)
        self.assertIn('spctl result: rejected (exit 3)', log)
        self.assertTrue(log.rstrip().endswith('RESULT: PASS'))
        self.assertIn('Executable=<mount>/ZeroPW.app/Contents/MacOS/zeropw-admin', log)
        self.assertNotIn(str(self.base), log)
        self.assertIsNone(self.runner.mounted)
        self.assertEqual(list((self.work / 'artifacts').iterdir()), [])

    def test_every_build_step_sees_only_the_allowlist_and_remapped_paths(self):
        self.assertEqual(self.package(), 0)
        allowed = set(self.module.BUILDER.ALLOWED_VARIABLES) | SET_BY_PACKAGER
        steps = [(c, env) for c, _, env in self.runner.calls if pathlib.Path(c[0]).name in ('npm', 'sh', 'tauri')]
        self.assertEqual(len(steps), 3)
        for command, environment in steps:
            with self.subTest(step=pathlib.Path(command[0]).name):
                self.assertLessEqual({key for key in environment if not key.startswith('LC_')}, allowed)
                self.assertEqual(environment['LC_CTYPE'], 'UTF-8')
                self.assertNotIn('/opt/local', ''.join(environment.values()))
                remaps = environment['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
                for path, neutral in ((self.work / 'source', '/zeropw'), (self.work, '/build'),
                                      (self.work / 'target', '/target'), (self.base / 'home/.cargo', '/cargo'),
                                      (self.base / 'home/.rustup', '/rustup'), (ROOT, '/checkout')):
                    self.assertIn(f'--remap-path-prefix={os.path.realpath(path)}={neutral}', remaps)
                self.assertIn(f'-ffile-prefix-map={self.work}=/build', environment['CFLAGS'].split())
        log = (self.out / LOG).read_text()
        for name in EXECUTABLES:
            self.assertIn(f'{name}: local paths: none (checked: the home directory, the work directory, the checkout, '
                          'CARGO_TARGET_DIR, CARGO_HOME, RUSTUP_HOME, /Volumes/, an account home (/Users/ or /home/))', log)

    def test_bundled_executables_are_compared_with_the_built_ones(self):
        self.assertEqual(self.package(), 0)
        log = (self.out / LOG).read_text()
        for name in EXECUTABLES:
            self.assertIn(f'{name}: unsigned, identical to the built binary (LC_UUID ', log)
        self.assertIn('zeropw-desktop (as linked by cargo, before bundling)', log)
        for name in SIDECARS:
            self.assertIn(f'  {name} (build-release.py --bin output; the src-tauri/binaries copy is identical)', log)
        removals = [c for c, _, _ in self.runner.calls if c[0] == 'codesign' and '--remove-signature' in c]
        self.assertEqual(len(removals), 2 * len(EXECUTABLES))
        self.assertFalse((self.work / 'artifacts/unsigned').exists())

    def test_a_different_bundled_executable_fails(self):
        cases = {
            'bytes differ from the built binary': macho(b'synthetic sidecar zeropw-agenT', uuid=b'\x32' * 16),
            'LC_UUID': macho(b'synthetic sidecar zeropw-agent', uuid=b'\x99' * 16),
            'still has a code signature': macho(b'synthetic sidecar zeropw-agent', uuid=b'\x32' * 16, signed=True),
            'not a thin 64-bit Mach-O': b'#!/bin/sh\nexit 0\n',
        }
        for message, data in cases.items():
            with self.subTest(message=message):
                shutil.rmtree(self.work, ignore_errors=True)
                self.runner = FakeRunner(self)
                self.runner.shipped = {'zeropw-agent': data}
                failure = self.failure()
                self.assertIn('zeropw-agent is not the binary the build produced', failure)
                self.assertIn(message, failure)
                self.assertFalse(self.out.exists())

    def test_bundled_sidecar_that_is_not_the_build_release_output_stops_before_tauri(self):
        self.runner.bundled_differs = True
        self.assertIn('is not the binary build-release.py produced', self.failure())
        self.assertNotIn('tauri', self.tools())

    def test_entitlements_on_any_executable_or_the_bundle_fail(self):
        plist = plistlib.dumps({'com.apple.security.get-task-allow': True}).decode()
        for name in ('zeropw-desktop', 'zeropw_session', 'ZeroPW.app'):
            with self.subTest(name=name):
                shutil.rmtree(self.work, ignore_errors=True)
                self.runner = FakeRunner(self)
                self.runner.entitlements = {name: plist}
                self.assertIn(f'{name} is signed with entitlements', self.failure())
                self.assertFalse(self.out.exists())
        self.assertTrue(self.module.no_entitlements(''))
        self.assertTrue(self.module.no_entitlements(plistlib.dumps({}).decode()))

    def test_files_unreadable_by_other_accounts_fail(self):
        self.runner.private = {'THIRD_PARTY_LICENSES.md'}
        failure = self.failure()
        self.assertIn('ZeroPW.app/Contents/Resources/THIRD_PARTY_LICENSES.md is not readable by every account', failure)
        self.assertEqual(list(self.out.iterdir()) if self.out.exists() else [], [])

    def test_local_paths_in_an_executable_fail(self):
        for label, embedded in (('the work directory', str(self.work) + '/target/release/build/out.rs'),
                                ('/Volumes/', '/Volumes/External/openssl/lib/ossl-modules'),
                                ('the home directory', str(self.base / 'home') + '/.cargo/registry/src/x.rs'),
                                ('an account home (/Users/ or /home/)', '/Users/someone-else/.cargo/registry/src/x.rs'),
                                ('an account home (/Users/ or /home/)', '/home/builder/.cargo/registry/src/x.rs')):
            with self.subTest(label=label):
                shutil.rmtree(self.work, ignore_errors=True)
                self.runner = FakeRunner(self)
                self.runner.shipped = {'zeropw-admin': None}

                def tamper(runner=self.runner, embedded=embedded):
                    path = self.work / f'source/desktop/src-tauri/binaries/zeropw-admin-{TARGET}'
                    runner.shipped['zeropw-admin'] = resign(path.read_bytes()) + embedded.encode()
                self.runner.during_tauri = tamper
                failure = self.failure()
                self.assertIn('zeropw-admin contains a local path: ' + label, failure)
                self.assertNotIn(str(self.base), self.log())

    def test_homebrew_or_non_system_linkage_in_any_executable_fails_and_ships_nothing(self):
        for library in ('/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib', '/opt/local/lib/libz.1.dylib',
                        '@rpath/libfoo.dylib'):
            with self.subTest(library=library):
                shutil.rmtree(self.work, ignore_errors=True)
                self.runner = FakeRunner(self)
                self.runner.otool['zeropw-admin'] = f'ZeroPW.app/Contents/MacOS/zeropw-admin:\n\t{library} (compatibility version 3.0.0)\n'
                self.assertIn(f'zeropw-admin links {library}', self.failure())
                self.assertFalse(self.out.exists())
                self.assertEqual(self.tools()[-1], 'hdiutil detach')
                self.assertIsNone(self.runner.mounted)

    def test_failed_signature_check_or_missing_notice_fails(self):
        self.runner.codesign_verify = 1
        self.assertIn('codesign --verify --deep --strict failed', self.failure())
        self.runner = FakeRunner(self)
        self.runner.omit = {'THIRD_PARTY_LICENSES.md', 'zeropw_session'}
        message = self.failure()
        self.assertIn('Resources/THIRD_PARTY_LICENSES.md is missing', message)
        self.assertIn('MacOS/zeropw_session is missing', message)
        self.assertFalse(self.out.exists())

    def test_image_that_does_not_mount_fails_with_its_record(self):
        self.runner.attach_fails = True
        self.assertIn('hdiutil attach failed', self.failure())
        log = (self.work / 'artifacts' / LOG).read_text()
        self.assertIn('hdiutil: attach failed - synthetic', log)
        self.assertTrue(log.rstrip().endswith('RESULT: FAIL'))
        self.assertFalse(self.out.exists())

    def test_image_that_does_not_detach_fails(self):
        self.runner.detach_fails = True
        self.assertIn('hdiutil detach failed; the image is still attached', self.failure())
        self.assertEqual(self.tools()[-2:], ['hdiutil detach', 'hdiutil detach'])
        self.assertIn('-force', self.runner.calls[-1][0])
        self.assertFalse(self.out.exists())

    def test_existing_artifacts_and_dirty_trees_are_refused(self):
        self.runner.status = ' M desktop/package.json\n'
        self.assertIn('tracked changes', self.failure())
        self.assertNotIn('tar', self.tools())
        self.runner = FakeRunner(self)
        self.out.mkdir()
        (self.out / DMG).write_bytes(b'already published')
        self.assertIn('refusing to replace ' + DMG, self.failure())
        self.assertNotIn('npm', self.tools())
        self.assertEqual((self.out / DMG).read_bytes(), b'already published')

    def test_an_artifact_that_appears_during_the_build_is_never_replaced(self):
        def intrude():
            self.out.mkdir(exist_ok=True)
            (self.out / (DMG + '.sha256')).write_text('from a concurrent run\n')
        self.runner.during_tauri = intrude
        message = self.failure()
        self.assertIn(f'refusing to replace {DMG}.sha256', message)
        self.assertIn('nothing was published', message)
        self.assertEqual(sorted(path.name for path in self.out.iterdir()), [DMG + '.sha256'])
        self.assertEqual((self.out / (DMG + '.sha256')).read_text(), 'from a concurrent run\n')
        self.assertTrue((self.work / 'artifacts' / DMG).is_file())

    def test_a_tag_is_required(self):
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.module.main(['--work-dir', str(self.work), '--out-dir', str(self.out)],
                                 environ=self.environ, runner=self.runner, system=('Darwin', 'arm64'))
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.runner.calls, [])

    def test_home_must_be_an_absolute_path(self):
        for home in (None, '', 'relative/home'):
            with self.subTest(home=home):
                environ = {k: v for k, v in self.environ.items() if k != 'HOME'}
                if home is not None:
                    environ['HOME'] = home
                self.assertIn('HOME must be set to an absolute path', self.failure(environ))
        self.assertEqual(self.runner.calls, [])

    def test_directories_inside_the_checkout_are_refused(self):
        tag = ['--tag', 'v0.1.0']
        for argv, environ in ((['--work-dir', str(ROOT / 'desktop/target/package'), '--out-dir', str(self.out), *tag], self.environ),
                              (['--work-dir', str(self.work), '--out-dir', str(ROOT / 'dist'), *tag], self.environ),
                              (['--work-dir', str(self.work), '--out-dir', str(self.out), *tag],
                               dict(self.environ, CARGO_TARGET_DIR=str(ROOT / 'rust/target')))):
            with self.subTest(argv=argv, target=environ.get('CARGO_TARGET_DIR')):
                with self.assertRaises(SystemExit) as raised:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.module.main(argv, environ=environ, runner=self.runner, system=('Darwin', 'arm64'))
                self.assertIn('must be outside the checkout', str(raised.exception))
        self.assertEqual(self.runner.calls, [])

    def test_cargo_target_dir_outside_the_checkout_is_honored(self):
        target = self.base / 'shared-target'
        self.assertEqual(self.package(dict(self.environ, CARGO_TARGET_DIR=str(target))), 0)
        tauri = next(env for c, _, env in self.runner.calls if pathlib.Path(c[0]).name == 'tauri')
        self.assertEqual(tauri['CARGO_TARGET_DIR'], str(target))
        self.assertIn(f'--remap-path-prefix={target}=/target', tauri['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'))
        self.assertTrue((target / 'release/zeropw-desktop').is_file())

    def test_a_work_directory_the_packager_does_not_own_is_refused_untouched(self):
        self.work.mkdir()
        (self.work / 'source').mkdir()
        (self.work / 'source/notes.txt').write_text('not ours\n')
        self.assertIn('was not created by package-macos', self.failure())
        self.assertEqual((self.work / 'source/notes.txt').read_text(), 'not ours\n')
        self.assertNotIn('archive', [c[3] for c, _, _ in self.runner.calls if c[0] == 'git'])
        # The packager's own work directory is reused.
        shutil.rmtree(self.work)
        self.runner = FakeRunner(self)
        self.assertEqual(self.package(), 0)
        self.assertTrue((self.work / '.zeropw-package-macos').is_file())
        shutil.rmtree(self.out)
        self.runner = FakeRunner(self)
        self.assertEqual(self.package(), 0)

    def test_linkage_filter(self):
        output = ('x:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n'
                  '\t/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit (compatibility version 1.0.0)\n')
        self.assertEqual(self.module.linkage_problems(output), [])
        for bad in ('/usr/local/lib/libfoo.dylib', '/opt/homebrew/lib/libz.dylib', '/usr/lib/libssl.48.dylib',
                    '@rpath/libcrypto.3.dylib', '/opt/local/lib/libz.1.dylib', '/nix/store/x-zlib/lib/libz.dylib',
                    '@executable_path/../Frameworks/libfoo.dylib'):
            self.assertEqual(self.module.linkage_problems(f'x:\n\t{bad} (compatibility version 1.0.0)\n'), [bad + ' (compatibility version 1.0.0)'])

    def test_unsigned_comparison_ignores_only_the_linkedit_vmsize(self):
        built = macho(b'payload')
        self.assertIsNone(self.module.unsigned_difference(resign(built), built))
        self.assertEqual(self.module.unsigned_difference(macho(b'payloaD'), built), 'bytes differ from the built binary')
        self.assertIn('LC_UUID', self.module.unsigned_difference(macho(b'payload', uuid=b'\x01' * 16), built))
        # A change in any other header field is a difference.
        changed = bytearray(built)
        changed[32 + 40] ^= 1  # __LINKEDIT fileoff
        self.assertEqual(self.module.unsigned_difference(bytes(changed), built), 'bytes differ from the built binary')
        self.assertIsNone(self.module.macho_layout(b'\xca\xfe\xba\xbe' + bytes(60)))


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

    def test_files_tauri_merges_on_its_own_are_refused(self):
        # A platform config could set bundle.macOS.entitlements, the CSP or capabilities, and
        # Tauri merges it into every build for that platform without any --config.
        platform_config = json.dumps({'bundle': {'macOS': {'entitlements': './x.plist'}}})
        for name in ('tauri.macos.conf.json', 'tauri.linux.conf.json5', 'tauri.windows.conf.json',
                     'tauri.ios.conf.json', 'tauri.android.conf.json', 'Tauri.macos.toml', 'Tauri.toml',
                     'tauri.conf.json5', 'TAURI.MACOS.CONF.JSON', 'Entitlements.plist', 'release.entitlements',
                     'info.plist'):
            with self.subTest(name=name):
                (self.tauri / name).write_text(platform_config)
                result = self.check()
                (self.tauri / name).unlink()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'src-tauri/{name}' if name != 'info.plist' else 'Info.plist would be merged', result.stderr)
        self.assertEqual(self.check().returncode, 0)

    def test_deep_link_is_exactly_the_zeropw_scheme(self):
        cases = [
            lambda c: c['plugins']['deep-link']['desktop'].update(domains=['example.com']),
            lambda c: c['plugins']['deep-link'].update(mobile=[{'host': 'example.com'}]),
            lambda c: c['plugins']['deep-link']['desktop'].update(name='ZeroPW link'),
            lambda c: c['plugins']['deep-link'].update(desktop=[{'schemes': ['zeropw'], 'domains': ['example.com']}]),
        ]
        for index, change in enumerate(cases):
            with self.subTest(case=index):
                original = (self.tauri / 'tauri.conf.json').read_text()
                self.edit('tauri.conf.json', change)
                result = self.check()
                (self.tauri / 'tauri.conf.json').write_text(original)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('plugins.deep-link must be exactly {"desktop":{"schemes":["zeropw"]}}', result.stderr)


if __name__ == '__main__':
    unittest.main()
