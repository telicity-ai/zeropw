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

    def supplement(self, entries, repositories=None):
        metadata = json.loads(self.root.joinpath('metadata.json').read_text())
        for package in metadata['packages']:
            package['repository'] = (repositories or {}).get(package['name'])
            package['authors'] = ['Synthetic Holder <holder@example.invalid>']
        self.root.joinpath('metadata.json').write_text(json.dumps(metadata))
        directory = self.root / 'reviewed'
        directory.mkdir(exist_ok=True)
        directory.joinpath('MIT.txt').write_text('Synthetic standard MIT text')
        directory.joinpath('supplement.json').write_text(json.dumps({'packages': entries}))
        return ('--include-development', '--supplement', str(directory / 'supplement.json'))

    def test_supplement_standard_text_covers_a_package_without_notice(self):
        result, notices = self.run_tool(*self.supplement({'devonly 1.0.0': {'license': 'MIT', 'standard_text': 'MIT'}}))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('### MIT (standard text)', notices)
        self.assertIn('Synthetic standard MIT text', notices)
        self.assertIn('Copyright holders declared in the package metadata: Synthetic Holder.', notices)
        self.assertNotIn('holder@example.invalid', notices)
        self.assertNotIn('manual review required', notices)

    def test_supplement_notices_from_the_same_repository_only(self):
        same = {'devonly': 'https://example.invalid/repo', 'runtime': 'https://example.invalid/repo'}
        entry = {'devonly 1.0.0': {'license': 'MIT', 'notices_from': 'runtime'}}
        result, notices = self.run_tool(*self.supplement(entry, same))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('### runtime 1.0.0: license-mit', notices)
        self.assertEqual(notices.count('Synthetic upstream notice for runtime'), 2)
        result = self.run_refused(*self.supplement(entry, dict(same, runtime='https://example.invalid/other')))
        self.assertIn('not from the same source repository', result.stderr)

    def run_refused(self, *args):
        env = dict(os.environ)
        env['PATH'] = str(self.root) + os.pathsep + env['PATH']
        output = self.root / 'refused.md'
        result = subprocess.run(['python3', str(SCRIPT), '--target', 'aarch64-unknown-linux-gnu',
                                 '--output', str(output), *args], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        return result

    def test_supplement_must_match_the_declared_license_and_an_offered_text(self):
        for entry, message in (({'license': 'Apache-2.0', 'standard_text': 'MIT'}, 'the package declares'),
                               ({'license': 'MIT', 'standard_text': 'Apache-2.0'}, 'offered under')):
            with self.subTest(message=message):
                result = self.run_refused(*self.supplement({'devonly 1.0.0': entry}))
                self.assertIn(message, result.stderr)
        result, notices = self.run_tool(*self.supplement({'devonly 0.9.0': {'license': 'MIT', 'standard_text': 'MIT'}}))
        self.assertEqual(result.returncode, 1)
        self.assertIn('devonly 1.0.0', result.stdout)
        self.assertIn('Supplement entries outside this closure: devonly 0.9.0', result.stdout)

if __name__ == '__main__':
    unittest.main()
