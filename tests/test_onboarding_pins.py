"""Release pins of the onboarding files follow Formula/zeropw.rb.

The schemas, validator, examples, guides, prompts and manuals each repeat the
formula's version, its two archive SHA-256 values and the formula file's own
SHA-256. These tests derive those values from the formula and require every
copy to match, so moving only some of the files to a new release fails. The
English and Korean manuals must also run the same commands.
"""
from collections import Counter
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ['artifact', 'install', 'local', 'policy']
GUIDES = ['docs/onboarding-validator.md', 'docs/onboarding-validator.ko.md']
PROMPTS = {'en': 'docs/team-agent-prompts.en.txt', 'ko': 'docs/team-agent-prompts.ko.txt'}
MANUALS = {'en': 'docs/team-onboarding.en.html', 'ko': 'docs/team-onboarding.ko.html'}
PINNED = ([f'docs/onboarding-schemas/{name}.schema.json' for name in SCHEMAS]
          + ['docs/onboarding-artifact.example.json', 'docs/onboarding-policy.example.json']
          + GUIDES + list(PROMPTS.values()) + list(MANUALS.values())
          + ['scripts/validate-onboarding.py'])
# Dated history that names an earlier release on purpose. Each must occur exactly once.
HISTORY = {
    'docs/onboarding-validator.md': ['The 2026-10-11 v0.1.0 onboarding test did not establish a `ready` pair.'],
    'docs/onboarding-validator.ko.md': ['2026-10-11 v0.1.0 온보딩 시험은 `ready` 쌍을 입증하지 못했다.'],
    'docs/team-onboarding.en.html': ['The 2026-10-11 v0.1.0 enrollment test was blocked by retained rejection history and did not establish a ready pair.'],
    'docs/team-onboarding.ko.html': ['2026-10-11 v0.1.0 가입 시험은 보존된 거절 기록 때문에 차단됐고 ready 쌍을 입증하지 못했다.'],
}
# A three-part version not embedded in a longer dotted number such as 10.8.0.2.
VERSION_TOKEN = re.compile(r'(?<![0-9.])[0-9]+\.[0-9]+\.[0-9]+(?![0-9]|\.[0-9])')
HEX64_TOKEN = re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])')
PROMPT_HEADER = re.compile(r'^\[(?:Prompt|프롬프트) ([0-9])[^\]\n]*\]\n', re.M)


def read(name):
    return (ROOT / name).read_text()


def formula():
    text = read('Formula/zeropw.rb')
    versions = re.findall(r'^  version "([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.M)
    assert len(versions) == 1, versions
    platforms = {}
    for name, start, end in [('macos', 'on_macos do', 'on_linux do'), ('linux', 'on_linux do', 'depends_on arch:')]:
        block = text[text.index(start):text.index(end)]
        urls = re.findall(r'^ +url "([^"]+)"$', block, re.M)
        digests = re.findall(r'^ +sha256 "([0-9a-f]{64})"$', block, re.M)
        assert len(urls) == 1 and len(digests) == 1, (name, urls, digests)
        platforms[name] = (urls[0], digests[0])
    return {'version': versions[0], 'tag': 'v' + versions[0], 'platforms': platforms,
            'mac': platforms['macos'][1], 'linux': platforms['linux'][1],
            'formula': hashlib.sha256((ROOT / 'Formula/zeropw.rb').read_bytes()).hexdigest()}


def code_blocks(name):
    return [html.unescape(block) for block in re.findall(r'<pre><code>(.*?)</code></pre>', read(name), re.S)]


def prompt_sections(name):
    text = read(name)
    headers = list(PROMPT_HEADER.finditer(text))
    sections = {}
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        sections[int(header.group(1))] = text[header.end():end].strip('\n')
    return sections


def pinned_enums(schema, name=None, out=None):
    """(property name, enum) pairs for the release fields, wherever they are nested."""
    out = Counter() if out is None else out
    if 'enum' in schema and name in {'release_tag', 'archive_sha256', 'formula_sha256', 'version'}:
        out[(name, tuple(schema['enum']))] += 1
    for key, child in schema.get('properties', {}).items():
        pinned_enums(child, key, out)
    for choice in schema.get('anyOf', []):
        pinned_enums(choice, name, out)
    for key in ['items', 'additionalProperties']:
        if isinstance(schema.get(key), dict):
            pinned_enums(schema[key], name, out)
    return out


class OnboardingPinTests(unittest.TestCase):
    def setUp(self):
        self.pins = formula()

    def test_formula_urls_name_its_version(self):
        p = self.pins
        base = f"https://github.com/telicity-ai/zeropw/releases/download/{p['tag']}/zeropw-{p['tag']}-"
        self.assertEqual(p['platforms']['macos'][0], base + 'aarch64-apple-darwin.tar.gz')
        self.assertEqual(p['platforms']['linux'][0], base + 'aarch64-unknown-linux-gnu.tar.gz')
        self.assertNotEqual(p['mac'], p['linux'])

    def test_every_version_and_digest_follows_the_formula(self):
        p = self.pins
        allowed = {p['mac'], p['linux'], p['formula']}
        for name in PINNED:
            with self.subTest(file=name):
                text = read(name)
                for phrase in HISTORY.get(name, []):
                    self.assertEqual(text.count(phrase), 1, phrase)
                    text = text.replace(phrase, '')
                versions = VERSION_TOKEN.findall(text)
                self.assertTrue(versions)
                self.assertEqual(set(versions), {p['version']})
                self.assertLessEqual(set(HEX64_TOKEN.findall(text)), allowed)

    def test_schemas_accept_only_the_formula_release(self):
        p = self.pins
        tag, archives, digest = ('release_tag', (p['tag'],)), ('archive_sha256', (p['mac'], p['linux'])), ('formula_sha256', (p['formula'],))
        version = ('version', (p['version'], 'unknown'))
        expected = {'artifact': Counter([tag, archives, digest]),
                    'install': Counter([tag, archives, digest, version]),
                    'local': Counter([tag, archives, digest, version]),
                    'policy': Counter([tag, archives, digest] * 2)}
        for name in SCHEMAS:
            with self.subTest(schema=name):
                schema = json.loads(read(f'docs/onboarding-schemas/{name}.schema.json'))
                self.assertEqual(pinned_enums(schema), expected[name])

    def test_validator_constants(self):
        spec = importlib.util.spec_from_file_location('onboarding_pins_validator', ROOT / 'scripts/validate-onboarding.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.RELEASE_VERSION, self.pins['version'])
        self.assertEqual(module.MACOS_ARCHIVE_SHA256, self.pins['mac'])

    def test_examples(self):
        p = self.pins
        artifact = json.loads(read('docs/onboarding-artifact.example.json'))
        self.assertEqual(artifact, {'release_tag': p['tag'], 'archive_sha256': p['mac'], 'tap_commit': '<VERIFIED_40_HEX_TAP_COMMIT>',
                                    'source': 'human_verified_release', 'formula_sha256': p['formula']})
        policy = json.loads(read('docs/onboarding-policy.example.json'))
        self.assertEqual(policy['artifact_receipts'], {'A': artifact, 'B': artifact})

    def test_guides(self):
        p = self.pins
        for name in GUIDES:
            with self.subTest(guide=name):
                text = read(name)
                self.assertIn(f"| ARM64 macOS | `{p['mac']}` |", text)
                self.assertIn(f"| ARM64 Linux | `{p['linux']}` |", text)
                self.assertIn(f"](https://github.com/telicity-ai/zeropw/releases/tag/{p['tag']})", text)
                self.assertIn(f"{p['tag']} formula SHA-256", text)
                self.assertIn(f"`{p['formula']}`", text)

    def test_manual_install_guards_pin_the_formula_and_match(self):
        guards = {}
        for language, name in MANUALS.items():
            with self.subTest(manual=name):
                guards[language] = code_blocks(name)[0]
                digests = re.findall(r'\| cut -d \' \' -f 1\)" = "([0-9a-f]{64})" \]', guards[language])
                self.assertEqual(digests, [self.pins['formula']])
                text = read(name)
                self.assertIn(f"/ {self.pins['tag']}</div>", text)
                self.assertIn(f"ZeroPW {self.pins['tag']} · ", text)
                self.assertIn(f"releases/tag/{self.pins['tag']}\"", text)
        self.assertEqual(guards['en'], guards['ko'])

    def test_manual_commands_match_across_languages(self):
        en, ko = code_blocks(MANUALS['en']), code_blocks(MANUALS['ko'])
        self.assertEqual(len(en), len(ko))
        for i, (left, right) in enumerate(zip(en, ko)):
            if 13 <= i <= 15:
                continue  # prompt copies, checked against each language's prompt file
            with self.subTest(block=i):
                strip = lambda block: [line for line in block.split('\n') if not line.lstrip().startswith('#')]
                self.assertEqual(strip(left), strip(right))

    def test_manual_prompt_copies_equal_prompt_files(self):
        for language in ['en', 'ko']:
            with self.subTest(language=language):
                sections = prompt_sections(PROMPTS[language])
                self.assertEqual(sorted(sections), [0, 1, 2])
                self.assertEqual(code_blocks(MANUALS[language])[13:16], [sections[0], sections[1], sections[2]])
                for section in sections.values():
                    self.assertIn(self.pins['version'], section)


if __name__ == '__main__':
    unittest.main()
