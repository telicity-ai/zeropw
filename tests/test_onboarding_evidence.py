"""Evidence binding check; included by the existing CI tests/test_*.py job."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EvidenceTests(unittest.TestCase):
    def test_reviewed_files_and_cases_are_bound_to_current_sources(self):
        manifest = json.loads((ROOT / 'docs/onboarding-validation-manifest.json').read_text())
        for name, digest in manifest['source_sha256'].items():
            with self.subTest(file=name):
                path = ROOT / name
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertGreaterEqual(len(manifest['cases']), 7)
        for case in manifest['cases']:
            with self.subTest(case=case['case']):
                self.assertEqual(case['source_sha256'], manifest['source_sha256'][case['source_file']])
                for field in ['input_sha256', 'response_sha256']:
                    self.assertRegex(case[field], r'^[0-9a-f]{64}$')
                self.assertEqual(case['actual_models'], ['claude-opus-5-5'])
                self.assertTrue(case['strict_json'])
                self.assertEqual(case['cli_exit'], 0)


if __name__ == '__main__':
    unittest.main()
