"""Scanner classification and value-free reports in synthetic Git repositories."""
import json
import pathlib
import subprocess
import tempfile
import unittest

SCANNER = pathlib.Path(__file__).resolve().parents[1] / 'scripts/audit-publication.py'

class PublicationAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)

    def scan(self, *args):
        result = subprocess.run(['python3', str(SCANNER), *args], cwd=self.root,
                                capture_output=True, text=True)
        return result, json.loads(result.stdout)

    def test_clean_tracked_file_passes_and_untracked_data_is_not_read(self):
        (self.root / 'source.txt').write_text('ordinary source\n')
        (self.root / 'untracked.txt').write_text('ghp_' + 'A' * 36)
        subprocess.run(['git', 'add', 'source.txt'], cwd=self.root, check=True)
        result, report = self.scan()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report['files_or_blobs_scanned'], 1)
        self.assertEqual(report['findings'], [])

    def test_matches_are_classified_without_printing_values(self):
        token = 'ghp_' + 'A' * 36
        source = token + '\n/Users/synthetic-owner/project/\n-----BEGIN PRIVATE KEY-----\n'
        (self.root / 'fixture.txt').write_text(source)
        subprocess.run(['git', 'add', 'fixture.txt'], cwd=self.root, check=True)
        result, report = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertEqual({f['rule'] for f in report['findings']},
                         {'github_token_shape', 'personal_absolute_path', 'private_key_marker'})
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn('synthetic-owner', result.stdout + result.stderr)

    def test_history_finds_removed_fixture_without_rewriting_it(self):
        (self.root / 'fixture.txt').write_text('ghp_' + 'B' * 36)
        subprocess.run(['git', 'add', 'fixture.txt'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.com',
                        'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        subprocess.run(['git', 'rm', '-q', 'fixture.txt'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.com',
                        'commit', '-qm', 'remove fixture'], cwd=self.root, check=True)
        tree_result, tree = self.scan()
        self.assertEqual(tree_result.returncode, 0)
        history_result, history = self.scan('--history')
        self.assertEqual(history_result.returncode, 1)
        self.assertEqual(history['findings'][0]['rule'], 'github_token_shape')
        self.assertTrue(history['findings'][0]['blob'])
        self.assertEqual(tree['findings'], [])

if __name__ == '__main__':
    unittest.main()
