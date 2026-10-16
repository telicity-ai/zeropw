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
HEADER = '| Case | Prompt file SHA-256 | Input SHA-256 | Response SHA-256 | Tool-log SHA-256 |\n'
ROW = re.compile(r'\| ([A-Za-z0-9-]+) \| ' + HEX + r' \| ' + HEX + r' \| ' + HEX + r' \| (?:' + HEX + r'|null \(no calls\)) \|')


class ReportTests(unittest.TestCase):
    def test_report_table_equals_manifest_cases(self):
        manifest = json.loads((ROOT / 'docs/onboarding-validation-manifest.json').read_text())
        expected = [(c['case'], c['source_sha256'], c['input_sha256'], c['response_sha256'], c['tool_log_sha256'])
                    for c in manifest['cases']]
        text = (ROOT / REPORT).read_text()
        self.assertEqual(text.count(HEADER), 1)
        table = text.split(HEADER, 1)[1].split('\n\n', 1)[0].strip('\n').split('\n')
        self.assertEqual(table[0], '| --- | --- | --- | --- | --- |')
        rows = []
        for line in table[1:]:
            match = ROW.fullmatch(line)
            self.assertIsNotNone(match, line)
            rows.append((match[1], match[2], match[3], match[4], match[5]))
        self.assertEqual(rows, expected)
        # No second copy of any case hash elsewhere, for example in a hidden comment.
        for case in manifest['cases']:
            self.assertEqual(text.count(case['input_sha256']), 1)


if __name__ == '__main__':
    unittest.main()
