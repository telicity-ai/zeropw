"""Installation boundaries using synthetic executables, never a real vault."""
import hashlib
import io
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINS = ('zeropw-admin', 'zeropw-agent', 'zeropw_session', 'zeropw-demo', 'zeropw-democli')

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.prefix = self.root / 'prefix with spaces'

    def archive(self, extra=None, missing=None):
        path = self.root / 'package.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name in BINS + ('README.md', 'LICENSE'):
                if name == missing:
                    continue
                content = b'#!/bin/sh\nprintf "synthetic fixture\\n"\n'
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755 if name in BINS else 0o644
                archive.addfile(info, io.BytesIO(content))
            if extra:
                archive.addfile(extra, io.BytesIO(b'') if extra.isfile() else None)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def run_install(self, archive, digest, *args):
        return subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--archive', str(archive),
                               '--sha256', digest, '--prefix', str(self.prefix), *args],
                              capture_output=True, text=True)

    def test_install_all_binaries_without_running_them(self):
        result = self.run_install(*self.archive())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(p.name for p in (self.prefix / 'bin').iterdir()), set(BINS))
        for name in BINS:
            self.assertTrue((self.prefix / 'bin' / name).stat().st_mode & 0o111)
        self.assertEqual(list(self.prefix.iterdir()), [self.prefix / 'bin'])

    def test_bad_checksum_leaves_prefix_untouched(self):
        path, _ = self.archive()
        result = self.run_install(path, '0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum mismatch', result.stderr)
        self.assertFalse(self.prefix.exists())

    def test_missing_helper_is_rejected(self):
        self.assertNotEqual(self.run_install(*self.archive(missing='zeropw_session')).returncode, 0)
        self.assertFalse(self.prefix.exists())

    def test_traversal_and_duplicate_entries_are_rejected(self):
        for name in ('../escaped', '/absolute', 'zeropw-agent'):
            with self.subTest(name=name):
                result = self.run_install(*self.archive(extra=tarfile.TarInfo(name)))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.prefix.exists())
        self.assertFalse((self.root / 'escaped').exists())

    def test_links_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            info = tarfile.TarInfo('zeropw-agent')
            info.type = kind
            info.linkname = '../outside'
            result = self.run_install(*self.archive(extra=info, missing='zeropw-agent'))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.prefix.exists())

    def test_existing_install_requires_force(self):
        archive = self.archive()
        self.assertEqual(self.run_install(*archive).returncode, 0)
        self.assertNotEqual(self.run_install(*archive).returncode, 0)
        self.assertEqual(self.run_install(*archive, '--force').returncode, 0)

    def test_force_replaces_symlink_without_modifying_target(self):
        self.prefix.joinpath('bin').mkdir(parents=True)
        outside = self.root / 'outside'
        outside.write_text('preserve me')
        self.prefix.joinpath('bin/zeropw-agent').symlink_to(outside)
        result = self.run_install(*self.archive(), '--force')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_text(), 'preserve me')
        self.assertFalse(self.prefix.joinpath('bin/zeropw-agent').is_symlink())

    def test_symlink_bin_directory_is_rejected(self):
        self.prefix.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        self.prefix.joinpath('bin').symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.run_install(*self.archive()).returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_explicit_prefix_and_help_work_without_home(self):
        env = dict(os.environ)
        env.pop('HOME', None)
        path, digest = self.archive()
        result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--archive', str(path),
                                 '--sha256', digest, '--prefix', str(self.prefix)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--help'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_version_is_rejected_without_network(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--version', '../bad'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('specify a release version', result.stderr)

if __name__ == '__main__':
    unittest.main()
