"""The v0.2.0 validation report's hash table matches the bound manifest.

The report is not in docs/onboarding-validation-manifest.json (it was written after the cases were
bound), so this keeps its published hashes from drifting away from the binding.
"""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = 'docs/onboarding-validation-v0.2.0-2026-10-16.md'
HEX = r'`([0-9a-f]{64})`'
ROW = re.compile(r'^\| ([A-Za-z0-9-]+) \| ' + HEX + r' \| ' + HEX + r' \| ' + HEX + r' \| (?:' + HEX + r'|null \(no calls\)) \|$', re.M)


class ReportTests(unittest.TestCase):
    def test_report_table_equals_manifest_cases(self):
        manifest = json.loads((ROOT / 'docs/onboarding-validation-manifest.json').read_text())
        expected = [(c['case'], c['source_sha256'], c['input_sha256'], c['response_sha256'], c['tool_log_sha256'])
                    for c in manifest['cases']]
        rows = [(m[0], m[1], m[2], m[3], m[4] or None) for m in ROW.findall((ROOT / REPORT).read_text())]
        self.assertEqual(rows, expected)


if __name__ == '__main__':
    unittest.main()
