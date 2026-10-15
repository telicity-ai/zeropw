import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('brew_observer', ROOT / 'scripts/observe-onboarding-brew.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
COMMIT = 'a' * 40


class BrewObserverTests(unittest.TestCase):
    def fixture(self, directory, spec='stable'):
        prefix = Path(directory) / 'keg'
        (prefix / 'bin').mkdir(parents=True)
        for name in v.BINARIES:
            binary = prefix / 'bin' / name
            binary.write_text('#!/bin/sh\nexit 99\n')
            binary.chmod(0o755)
        (prefix / 'INSTALL_RECEIPT.json').write_text(json.dumps({'source': {'tap_git_head': COMMIT, 'spec': spec}}))
        return prefix

    def test_actual_receipt_and_all_five_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.fixture(directory)
            result = v.observe(prefix, str(prefix / 'bin'))
            self.assertEqual(result, {'installed_tap_commit': COMMIT, 'installed_spec': 'stable', 'binaries_resolve_to_keg': True})
            self.assertNotIn(str(prefix), json.dumps(result))

    def test_path_shadow_and_missing_helper_block(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.fixture(directory)
            shadow = Path(directory) / 'shadow'
            shadow.mkdir()
            binary = shadow / 'zeropw-agent'
            binary.write_text('#!/bin/sh\nexit 99\n'); binary.chmod(0o755)
            self.assertFalse(v.observe(prefix, str(shadow) + os.pathsep + str(prefix / 'bin'))['binaries_resolve_to_keg'])
            (prefix / 'bin/zeropw_session').unlink()
            self.assertFalse(v.observe(prefix, str(prefix / 'bin'))['binaries_resolve_to_keg'])

    def test_malformed_metadata_does_not_echo_data(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.fixture(directory)
            for data in [{'source': []}, 'not-an-object']:
                (prefix / 'INSTALL_RECEIPT.json').write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, '^invalid_brew_receipt$'):
                    v.observe(prefix, str(prefix / 'bin'))

    def test_cli_approval_and_head_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.fixture(directory)
            for spec, approved, expected in [('stable', COMMIT, 0), ('stable', 'b' * 40, 1), ('head', COMMIT, 1)]:
                (prefix / 'INSTALL_RECEIPT.json').write_text(json.dumps({'source': {'tap_git_head': COMMIT, 'spec': spec}}))
                with mock.patch.dict(os.environ, {'PATH': str(prefix / 'bin')}), mock.patch.object(v.shutil, 'which', side_effect=lambda name, **kwargs: '/trusted/brew' if name == 'brew' else str(prefix / 'bin' / name)), mock.patch.object(v.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, str(prefix) + '\n', '')), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(v.main(['--approved-tap', approved]), expected)
                self.assertNotIn(str(prefix), output.getvalue())

    def test_child_does_not_inherit_capabilities_or_other_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.fixture(directory)
            with mock.patch.dict(os.environ, {'PATH': str(prefix / 'bin'), 'SYNTHETIC_MODEL_KEY': 'not-real', 'ZEROPW_CALLER_TOKEN': 'caller-fixture'}), mock.patch.object(v.shutil, 'which', side_effect=lambda name, **kwargs: '/trusted/brew' if name == 'brew' else str(prefix / 'bin' / name)), mock.patch.object(v.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, str(prefix), '')) as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(v.main(['--approved-tap', COMMIT]), 0)
                child = run.call_args.kwargs['env']
                self.assertNotIn('SYNTHETIC_MODEL_KEY', child)
                self.assertNotIn('ZEROPW_CALLER_TOKEN', child)
                self.assertEqual(child['HOMEBREW_NO_AUTO_UPDATE'], '1')


if __name__ == '__main__':
    unittest.main()
