"""scripts/build-release.py --bin: named release binaries without an archive, using fakes only."""
import contextlib
import hashlib
import importlib.util
import io
import os
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIDECARS = ('zeropw-admin', 'zeropw_session', 'zeropw-agent')


def load_builder():
    spec = importlib.util.spec_from_file_location('release_builder_bins', ROOT / 'scripts/build-release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseBinariesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = pathlib.Path(temp.name) / 'out'
        self.module = load_builder()
        self.commands = []
        self.linkage = []
        self.bad_linkage = set()
        # A synthetic OpenSSL source archive, already "downloaded", accepted by its digest.
        work = self.out / 'openssl-build'
        work.mkdir(parents=True)
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
                (release / name).write_bytes(b'synthetic binary ' + name.encode())
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
        self.assertEqual(environment['OPENSSL_DIR'], str(self.out.resolve() / 'openssl-build/sdk'))
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
                      ['--bin', 'zeropw-admin', '--version', 'v0.1.0'], []):
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
        self.build('--version', 'v0.1.0')
        bins = self.module.load_packager(ROOT).BINS
        cargo = [command for command, _ in self.commands if command[:2] == ['cargo', 'build']]
        self.assertEqual(len(cargo), 1)
        self.assertIn('--bins', cargo[0])
        self.assertNotIn('--bin', cargo[0])
        self.assertEqual([name for name, _ in self.linkage], list(bins))
        package = self.tool_calls('package-release.py')
        self.assertEqual(len(package), 1)
        self.assertEqual(package[0][package[0].index('--version') + 1], 'v0.1.0')
        self.assertFalse((self.out / 'bin').exists())

    def test_release_environment_is_not_inherited_by_the_selected_build(self):
        with mock.patch.dict(os.environ, {'OPENSSL_LIB_DIR': '/untrusted', 'RUSTFLAGS': '-L/untrusted',
                                          'CARGO_TARGET_DIR': '/elsewhere'}):
            self.build(*self.sidecar_args())
        _, environment = next((c, e) for c, e in self.commands if c[:2] == ['cargo', 'build'])
        self.assertNotIn('OPENSSL_LIB_DIR', environment)
        self.assertNotIn('RUSTFLAGS', environment)
        self.assertEqual(environment['CARGO_TARGET_DIR'], str(self.out.resolve() / 'cargo-target'))


if __name__ == '__main__':
    unittest.main()
