"""scripts/build-release.py: release binaries and archives, using fakes only.

Covers --bin (named binaries without an archive), the output directory the builder owns, the
allowlisted environment, source path remapping and the local path check on built binaries.
"""
import contextlib
import hashlib
import importlib.util
import io
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')
SET_BY_BUILDER = {'OPENSSL_DIR', 'OPENSSL_STATIC', 'CARGO_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS', 'CFLAGS'}


def load_builder():
    spec = importlib.util.spec_from_file_location('release_builder_bins', ROOT / 'scripts/build-release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def product_version():
    """v<the [package] version of rust/Cargo.toml>, whatever the release."""
    text = (ROOT / 'rust/Cargo.toml').read_text()
    return 'v' + re.search(r'^\[package\][^\[]*?^version = "([^"]+)"', text, re.M | re.S).group(1)


class ReleaseBinariesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = pathlib.Path(temp.name) / 'out'
        self.module = load_builder()
        self.commands = []
        self.linkage = []
        self.bad_linkage = set()
        self.embedded = {}
        # A synthetic OpenSSL source archive, already "downloaded", accepted by its digest.
        work = self.out / 'openssl-build'
        work.mkdir(parents=True)
        # An earlier run of the builder left its marker: the directory is the builder's own.
        (self.out / '.zeropw-build-release').write_text('earlier run\n')
        archive = work / 'openssl-3.5.9.tar.gz'
        with tarfile.open(archive, 'w:gz') as contents:
            for name, data in (('openssl-3.5.9/LICENSE.txt', b'Synthetic OpenSSL notice\n'),):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                contents.addfile(info, io.BytesIO(data))
        patches = [
            mock.patch.object(self.module, 'OPENSSL_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest()),
            mock.patch.object(self.module, 'run', side_effect=self.fake_run),
            mock.patch.object(self.module, 'verify_linkage', side_effect=self.fake_linkage),
            mock.patch.object(self.module.platform, 'system', return_value='Darwin'),
            mock.patch.object(self.module.platform, 'machine', return_value='arm64'),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def fake_run(self, command, cwd, environment):
        self.commands.append((list(command), dict(environment)))
        if command[:2] == ['cargo', 'build']:
            release = pathlib.Path(environment['CARGO_TARGET_DIR']) / 'aarch64-apple-darwin/release'
            release.mkdir(parents=True, exist_ok=True)
            names = [command[i + 1] for i, part in enumerate(command) if part == '--bin']
            for name in names or self.module.load_packager(ROOT).BINS:
                (release / name).write_bytes(b'synthetic binary ' + name.encode() + self.embedded.get(name, b''))
        elif command[0] == 'python3' and command[1].endswith('dependency-licenses.py'):
            output = pathlib.Path(command[command.index('--output') + 1])
            output.write_text('# Third-party dependency licenses\nTarget: aarch64-apple-darwin.\n')

    def fake_linkage(self, binary, system):
        self.linkage.append((binary.name, system))
        if binary.name in self.bad_linkage:
            raise SystemExit('release binary has an unexpected dynamic dependency: ' + binary.name)

    def build(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.module.main(['--target', 'aarch64-apple-darwin', '--out-dir', str(self.out), *extra])

    def sidecar_args(self):
        return [part for name in SIDECARS for part in ('--bin', name)]

    def tool_calls(self, suffix):
        return [command for command, _ in self.commands if command[0] == 'python3' and command[1].endswith(suffix)]

    def test_named_binaries_are_built_statically_checked_and_copied_without_an_archive(self):
        self.build(*self.sidecar_args())
        cargo = [(command, env) for command, env in self.commands if command[:2] == ['cargo', 'build']]
        self.assertEqual(len(cargo), 1)
        command, environment = cargo[0]
        self.assertIn('bundled-openssl', command[command.index('--features') + 1].split(','))
        self.assertNotIn('--bins', command)
        self.assertEqual([command[i + 1] for i, part in enumerate(command) if part == '--bin'], list(SIDECARS))
        self.assertEqual(environment['OPENSSL_STATIC'], '1')
        self.assertEqual(environment['OPENSSL_DIR'],
                         str(self.out.resolve() / 'openssl-build/sdk/nonexistent/zeropw-openssl'))
        self.assertEqual(self.linkage, [(name, 'Darwin') for name in SIDECARS])
        notices = self.tool_calls('dependency-licenses.py')
        self.assertEqual(len(notices), 1)
        self.assertIn('--openssl-source', notices[0])
        self.assertEqual(self.tool_calls('package-release.py'), [])
        self.assertEqual(list(self.out.glob('*.tar.gz')), [])
        copied = self.out / 'bin'
        self.assertEqual(sorted(path.name for path in copied.iterdir()), sorted(SIDECARS))
        for name in SIDECARS:
            self.assertEqual((copied / name).read_bytes(), b'synthetic binary ' + name.encode())
            self.assertEqual((copied / name).stat().st_mode & 0o777, 0o755)

    def test_dynamic_openssl_linkage_leaves_no_binaries_behind(self):
        stale = self.out / 'bin'
        stale.mkdir()
        (stale / 'zeropw-admin').write_bytes(b'from an earlier build')
        self.bad_linkage.add('zeropw-agent')
        with self.assertRaises(SystemExit):
            self.build(*self.sidecar_args())
        self.assertFalse(stale.exists())
        self.assertEqual(self.tool_calls('dependency-licenses.py'), [])

    def test_rejects_unknown_duplicate_or_versioned_selection_before_building(self):
        for extra in (['--bin', 'zeropw-desktop'], ['--bin', 'zeropw-admin', '--bin', 'zeropw-admin'],
                      ['--bin', 'zeropw-admin', '--version', product_version()], []):
            with self.subTest(extra=extra):
                with self.assertRaises(SystemExit) as raised:
                    self.build(*extra)
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.commands, [])

    def test_non_native_target_is_refused(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self.module.main(['--target', 'x86_64-apple-darwin', '--out-dir', str(self.out), '--bin', 'zeropw-admin'])
        self.assertEqual(self.commands, [])

    def test_openssl_source_checksum_mismatch_stops_before_any_build(self):
        with mock.patch.object(self.module, 'OPENSSL_SHA256', '0' * 64):
            with self.assertRaises(SystemExit) as raised:
                self.build(*self.sidecar_args())
        self.assertIn('checksum mismatch', str(raised.exception))
        self.assertEqual(self.commands, [])

    def test_archive_mode_still_builds_checks_and_packages_all_release_binaries(self):
        self.build('--version', product_version())
        bins = self.module.load_packager(ROOT).BINS
        cargo = [command for command, _ in self.commands if command[:2] == ['cargo', 'build']]
        self.assertEqual(len(cargo), 1)
        self.assertIn('--bins', cargo[0])
        self.assertNotIn('--bin', cargo[0])
        self.assertEqual([name for name, _ in self.linkage], list(bins))
        package = self.tool_calls('package-release.py')
        self.assertEqual(len(package), 1)
        self.assertEqual(package[0][package[0].index('--version') + 1], product_version())
        self.assertFalse((self.out / 'bin').exists())

    def test_archive_version_must_be_the_product_version(self):
        major, minor, patch = (int(part) for part in product_version()[1:].split('.'))
        for version in (f'v{major + 1}.{minor}.{patch}', f'v{major}.{minor}.{patch + 1}'):
            with self.subTest(version=version):
                with self.assertRaises(SystemExit) as raised:
                    self.build('--version', version)
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(self.commands, [])

    def test_release_environment_is_not_inherited_by_the_selected_build(self):
        with mock.patch.dict(os.environ, {'OPENSSL_LIB_DIR': '/untrusted', 'RUSTFLAGS': '-L/untrusted',
                                          'CARGO_TARGET_DIR': '/elsewhere'}):
            self.build(*self.sidecar_args())
        _, environment = next((c, e) for c, e in self.commands if c[:2] == ['cargo', 'build'])
        self.assertNotIn('OPENSSL_LIB_DIR', environment)
        self.assertNotIn('RUSTFLAGS', environment)
        self.assertEqual(environment['CARGO_TARGET_DIR'], str(self.out.resolve() / 'cargo-target'))

    def test_every_step_runs_with_the_allowlisted_environment(self):
        inherited = {'PATH': '/usr/bin:/bin', 'HOME': str(self.out.parent / 'home'), 'LANG': 'C.UTF-8',
                     'LC_ALL': 'C.UTF-8', 'MACOSX_DEPLOYMENT_TARGET': '11.0',
                     'ZEROPW_CALLER_TOKEN': 'synthetic', 'GH_TOKEN': 'synthetic', 'CSC_LINK': 'synthetic',
                     'SSH_AUTH_SOCK': '/tmp/synthetic.sock', 'NPM_TOKEN': 'synthetic',
                     'RUSTFLAGS': '-C target-cpu=native', 'CC': '/opt/local/bin/clang',
                     'LIBRARY_PATH': '/opt/local/lib', 'DYLD_INSERT_LIBRARIES': '/tmp/synthetic.dylib',
                     'HTTPS_PROXY': 'http://synthetic@proxy.invalid', 'TAURI_CONFIG': '{}'}
        with mock.patch.dict(os.environ, inherited, clear=True):
            self.build(*self.sidecar_args())
        allowed = set(self.module.ALLOWED_VARIABLES) | {'MACOSX_DEPLOYMENT_TARGET'} | SET_BY_BUILDER
        self.assertGreater(len(self.commands), 3)
        for command, environment in self.commands:
            with self.subTest(command=command[:2]):
                self.assertLessEqual({key for key in environment if not key.startswith('LC_')}, allowed)
                self.assertNotIn('synthetic', ''.join(environment.values()))
        _, environment = next((c, e) for c, e in self.commands if c[:2] == ['cargo', 'build'])
        for key in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'MACOSX_DEPLOYMENT_TARGET'):
            self.assertEqual(environment[key], inherited[key])

    def test_malformed_deployment_target_is_refused(self):
        with mock.patch.dict(os.environ, {'MACOSX_DEPLOYMENT_TARGET': '11.0 -L/untrusted'}):
            with self.assertRaises(SystemExit) as raised:
                self.build(*self.sidecar_args())
        self.assertIn('MACOSX_DEPLOYMENT_TARGET', str(raised.exception))
        self.assertEqual(self.commands, [])

    def test_output_directory_the_builder_does_not_own_is_refused_untouched(self):
        # An install prefix such as ~/.local: OUT_DIR/bin holds someone else's tools.
        prefix = self.out.parent / 'prefix'
        (prefix / 'bin').mkdir(parents=True)
        (prefix / 'bin/unrelated-tool').write_bytes(b'not ours')
        for target in (prefix, prefix / 'bin/unrelated-tool'):
            with self.subTest(target=target.name):
                with self.assertRaises(SystemExit) as raised:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.module.main(['--target', 'aarch64-apple-darwin', '--out-dir', str(target),
                                          *self.sidecar_args()])
                self.assertIn('build-release', str(raised.exception))
        self.assertEqual((prefix / 'bin/unrelated-tool').read_bytes(), b'not ours')
        self.assertEqual(sorted(path.name for path in prefix.rglob('*')), ['bin', 'unrelated-tool'])
        self.assertEqual(self.commands, [])

    def test_new_or_empty_output_directory_is_claimed_with_a_marker(self):
        for name in ('new', 'empty'):
            with self.subTest(name=name):
                fresh = self.out.parent / name
                if name == 'empty':
                    fresh.mkdir()
                with mock.patch.object(self.module, 'run', side_effect=SystemExit('download refused in tests')):
                    with self.assertRaises(SystemExit):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.module.main(['--target', 'aarch64-apple-darwin', '--out-dir', str(fresh),
                                              *self.sidecar_args()])
                self.assertTrue((fresh / '.zeropw-build-release').is_file())

    def test_openssl_has_a_neutral_prefix_and_is_installed_with_destdir(self):
        self.build(*self.sidecar_args())
        configure = next(command for command, _ in self.commands if command[:2] == ['perl', 'Configure'])
        self.assertIn('--prefix=/nonexistent/zeropw-openssl', configure)
        self.assertFalse(any(str(self.out.resolve()) in part for part in configure))
        install = next(command for command, _ in self.commands if command[:2] == ['make', 'install_sw'])
        self.assertEqual(install[2:], ['DESTDIR=' + str(self.out.resolve() / 'openssl-build/sdk')])

    def test_rust_and_c_source_paths_are_remapped(self):
        home = self.out.parent / 'home'
        with mock.patch.dict(os.environ, {'HOME': str(home), 'CARGO_HOME': str(home / 'cargo-home')}):
            os.environ.pop('RUSTUP_HOME', None)
            self.build(*self.sidecar_args())
        _, environment = next((c, e) for c, e in self.commands if c[:2] == ['cargo', 'build'])
        flags = environment['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')
        self.assertTrue(all(flag.startswith('--remap-path-prefix=') for flag in flags), flags)
        remaps = [flag.split('=', 1)[1] for flag in flags]
        for path, neutral in ((home / 'cargo-home', '/cargo'), (home / '.rustup', '/rustup'),
                              (ROOT, '/zeropw'), (self.out.resolve(), '/build')):
            self.assertIn(f'{os.path.realpath(path)}={neutral}', remaps)
        # rustc applies the last matching prefix: the more specific path comes later.
        lengths = [len(remap.rsplit('=', 1)[0]) for remap in remaps]
        self.assertEqual(lengths, sorted(lengths))
        self.assertIn(f'-ffile-prefix-map={os.path.realpath(ROOT)}=/zeropw', environment['CFLAGS'].split())
        # OpenSSL is built before the remapping applies, from relative paths inside its source.
        configure_env = next(e for c, e in self.commands if c[:2] == ['perl', 'Configure'])
        self.assertNotIn('CFLAGS', configure_env)
        self.assertNotIn('CARGO_ENCODED_RUSTFLAGS', configure_env)

    def test_a_binary_holding_a_local_path_is_refused(self):
        home = (self.out.parent / 'home').resolve()
        cases = {'the checkout': str(ROOT).encode() + b'/rust/src/main.rs',
                 'the home directory': str(home).encode() + b'/.cargo/registry/src/x.rs',
                 '/Volumes/': b'/Volumes/external/openssl/lib/engines-3',
                 'the output directory': str(self.out.resolve()).encode() + b'/openssl-build/sdk/lib'}
        for label, embedded in cases.items():
            with self.subTest(label=label):
                self.commands.clear()
                self.embedded = {'zeropw_session': b'\0' + embedded + b'\0'}
                with mock.patch.dict(os.environ, {'HOME': str(home)}):
                    with self.assertRaises(SystemExit) as raised:
                        self.build(*self.sidecar_args())
                self.assertIn('zeropw_session contains a local path', str(raised.exception))
                self.assertIn(label, str(raised.exception))
                self.assertNotIn(str(home), str(raised.exception))
                self.assertFalse((self.out / 'bin').exists())
                self.assertEqual(self.tool_calls('dependency-licenses.py'), [])


class MacosLinkageTests(unittest.TestCase):
    """On macOS a release binary may link only /usr/lib and /System/Library, never libssl/libcrypto."""

    def test_only_system_libraries(self):
        module = load_builder()
        header = 'synthetic:\n'
        allowed = ('\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n'
                   '\t/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0)\n')
        result = subprocess.CompletedProcess([], 0, stdout=header + allowed)
        with mock.patch.object(module.subprocess, 'run', return_value=result):
            module.verify_linkage(pathlib.Path('/tmp/synthetic'), 'Darwin')
        for bad in ('/opt/local/lib/libz.1.dylib', '/nix/store/abc-zlib/lib/libz.dylib', '@rpath/libfoo.dylib',
                    '/usr/lib/libssl.48.dylib', '/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib'):
            with self.subTest(bad=bad):
                output = header + allowed + f'\t{bad} (compatibility version 1.0.0)\n'
                result = subprocess.CompletedProcess([], 0, stdout=output)
                with mock.patch.object(module.subprocess, 'run', return_value=result):
                    with self.assertRaises(SystemExit):
                        module.verify_linkage(pathlib.Path('/tmp/synthetic'), 'Darwin')


if __name__ == '__main__':
    unittest.main()
