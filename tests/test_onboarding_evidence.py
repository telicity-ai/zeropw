"""Evidence binding check; included by the existing CI tests/test_*.py job."""
import hashlib
import ast
import html
import re
import subprocess
import tempfile
import os
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


    def test_receipt_and_downloaded_html_acceptance_links(self):
        for language in ['en','ko']:
            text=(ROOT/f'docs/team-agent-prompts.{language}.txt').read_text()
            receipt,_=json.JSONDecoder().raw_decode(text[text.index('{\n'):])
            document=(ROOT/f'docs/team-onboarding.{language}.html').read_text()
            blocks=re.findall(r'<pre><code>(.*?)</code></pre>',document,re.S)
            self.assertEqual(json.loads(html.unescape(blocks[12])),receipt)
            self.assertIn('^[a-z0-9_.-]{1,96}$',document[:document.index('Prompt 0') if language=='en' else document.index('프롬프트 0')])
            for link in re.findall(r'href="([^"]+)"',document):
                if 'onboarding-validator' in link or 'onboarding-policy' in link or 'onboarding-artifact' in link or 'onboarding-schemas' in link:
                    self.assertTrue(link.startswith('https://github.com/telicity-ai/zeropw/blob/'))
            self.assertIn('python3 scripts/validate-onboarding.py pair A.json B.json --policy policy.json',document)

    def test_all_validator_codes_are_published_in_both_guides(self):
        tree=ast.parse((ROOT/'scripts/validate-onboarding.py').read_text())
        codes=set()
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):continue
            target=node.func
            if not ((isinstance(target,ast.Name) and target.id=='ValueError') or (isinstance(target,ast.Attribute) and target.attr=='add')):continue
            if not node.args:continue
            value=node.args[0]
            while isinstance(value,ast.BinOp):value=value.left
            if isinstance(value,ast.Constant) and isinstance(value.value,str):codes.add(value.value.split(':')[0])
        for guide in ['onboarding-validator.md','onboarding-validator.ko.md']:
            text=(ROOT/'docs'/guide).read_text()
            for code in codes:self.assertIn('`'+code+'`',text)


    def test_human_install_guard_stops_before_formula_execution(self):
        document=(ROOT/'docs/team-onboarding.en.html').read_text()
        recipe=html.unescape(re.findall(r'<pre><code>(.*?)</code></pre>',document,re.S)[0])
        prefix=recipe.split('brew install telicity-ai/zeropw/zeropw',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory);(d/'Formula').mkdir();(d/'Formula/zeropw.rb').write_bytes((ROOT/'Formula/zeropw.rb').read_bytes())
            env={**os.environ,'GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_SYSTEM':os.devnull}
            for args in [['init','-q'],['add','Formula/zeropw.rb'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture']]:subprocess.run(['git','-C',str(d),*args],env=env,check=True,capture_output=True)
            head=subprocess.check_output(['git','-C',str(d),'rev-parse','HEAD'],env=env,text=True).strip()
            stub='brew() { if [ "$1" = "tap" ]; then return 0; fi; if [ "$1" = "--repository" ]; then printf "%s\\n" "$ZPW_TEST_REPO"; return 0; fi; return 99; }\n'
            for case in ['valid','wrong_commit','dirty','wrong_formula']:
                if case=='dirty':(d/'unapproved.txt').write_text('fixture')
                if case=='wrong_formula':(d/'unapproved.txt').unlink();(d/'Formula/zeropw.rb').write_text('unapproved fixture')
                approved='a'*40 if case=='wrong_commit' else head
                run=subprocess.run(['bash','-c',stub+prefix.replace('<HUMAN_VERIFIED_40_HEX_COMMIT>',approved)+'printf "reached_install_boundary"'],env={**env,'ZPW_TEST_REPO':str(d)},capture_output=True,text=True)
                if case=='valid':self.assertEqual(run.returncode,0);self.assertIn('reached_install_boundary',run.stdout)
                else:self.assertNotEqual(run.returncode,0);self.assertNotIn('reached_install_boundary',run.stdout)


if __name__ == '__main__':
    unittest.main()
