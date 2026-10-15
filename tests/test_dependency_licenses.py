"""Verify target closure and original notices using synthetic Cargo metadata."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'scripts/dependency-licenses.py'

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
        metadata = {'workspace_members': ['workspace'], 'packages': packages,
                    'resolve': {'nodes': [
                        {'id': 'workspace', 'deps': [
                            {'pkg': 'runtime', 'dep_kinds': [{'kind': None}]},
                            {'pkg': 'builder', 'dep_kinds': [{'kind': 'build'}]},
                            {'pkg': 'devonly', 'dep_kinds': [{'kind': 'dev'}]}]},
                        *({'id': name, 'deps': []} for name in ('runtime', 'builder', 'devonly'))]}}
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        self.root.joinpath('cargo').write_text('#!/bin/sh\ncat "' + str(self.root / 'metadata.json') + '"\n')
        self.root.joinpath('cargo').chmod(0o755)

    def run_tool(self, *args):
        env = dict(os.environ)
        env['PATH'] = str(self.root) + os.pathsep + env['PATH']
        output = self.root / 'notices.md'
        result = subprocess.run(['python3', str(SCRIPT), '--target', 'aarch64-unknown-linux-gnu',
                                 '--output', str(output), *args],
                                env=env, capture_output=True, text=True)
        return result, output.read_text()

    def test_runtime_and_build_notices_retained_without_cache_paths(self):
        result, notices = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('## runtime 1.0.0', notices)
        self.assertIn('## builder 1.0.0', notices)
        self.assertIn('Synthetic upstream notice for runtime', notices)
        self.assertNotIn('## devonly', notices)
        self.assertNotIn(str(self.root), notices)

    def test_complete_graph_requires_missing_development_notice(self):
        result, notices = self.run_tool('--include-development')
        self.assertEqual(result.returncode, 1)
        self.assertIn('devonly 1.0.0', result.stdout)
        self.assertIn('manual review required', notices)

    def test_symlink_notice_is_not_read(self):
        license_path = self.root / 'runtime/license-mit'
        license_path.unlink()
        outside = self.root / 'outside'
        outside.write_text('do not read this content')
        license_path.symlink_to(outside)
        result, notices = self.run_tool()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('do not read this content', notices)

if __name__ == '__main__':
    unittest.main()
