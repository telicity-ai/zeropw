"""Release download, failure cleanup and source pinning boundaries."""
import functools
import hashlib
import http.server
import importlib.util
import os
import pathlib
import platform
import shlex
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest

import test_installer as fixtures

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseFixTests(unittest.TestCase):
    def fixture(self):
        fixture = fixtures.InstallerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_version_download_uses_produced_checksum_asset_over_verified_tls(self):
        if not shutil.which('openssl') or not shutil.which('curl'):
            self.fail('TLS download verification requires openssl and curl')
        fixture = self.fixture()
        archive, digest = fixture.archive()
        targets = {('Darwin', 'arm64'): 'aarch64-apple-darwin',
                   ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
                   ('Linux', 'aarch64'): 'aarch64-unknown-linux-gnu',
                   ('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu'}
        target = targets[(platform.system(), platform.machine())]
        name = f'zeropw-v0.1.0-{target}.tar.gz'
        assets = fixture.root / 'assets/telicity-ai/zeropw/releases/download/v0.1.0'
        assets.mkdir(parents=True)
        shutil.copy(archive, assets / name)
        checksum = assets / (name + '.sha256')
        certificate, key = fixture.root / 'cert.pem', fixture.root / 'synthetic.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1',
                        '-subj', '/CN=github.com', '-addext', 'subjectAltName=DNS:github.com'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0),
                     functools.partial(Handler, directory=str(fixture.root / 'assets')))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tools = fixture.root / 'tools'
        tools.mkdir()
        real_curl = shutil.which('curl')
        (tools / 'curl').write_text('#!/bin/sh\nexec ' + shlex.quote(real_curl) +
            ' --noproxy "*" --cacert ' + shlex.quote(str(certificate)) +
            f' --connect-to github.com:443:127.0.0.1:{server.server_port} "$@"\n')
        (tools / 'curl').chmod(0o755)
        environment = {'PATH': str(tools) + os.pathsep + os.defpath}
        for label, content, success in [
            ('valid with unrelated entry', f'{digest}  {name}\n' + '0'*64 + '  other.tar.gz\n', True),
            ('missing matching entry', '0'*64 + '  other.tar.gz\n', False),
            ('duplicate matching entry', f'{digest}  {name}\n{digest}  {name}\n', False),
        ]:
            with self.subTest(label=label):
                checksum.write_text(content)
                prefix = fixture.root / label
                result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--version',
                         'v0.1.0', '--prefix', str(prefix)], env=environment,
                         capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertTrue((prefix / 'bin/zeropw-agent').is_file())
                else:
                    self.assertFalse(prefix.exists())

    def test_doc_stage_failure_removes_already_created_binary_stage(self):
        fixture = self.fixture()
        tools = fixture.root / 'tools'
        tools.mkdir()
        command = tools / 'mktemp'
        command.write_text('#!/bin/sh\ncase "$*" in *zeropw-docs*) exit 71;; esac\nexec ' +
                           shlex.quote(shutil.which('mktemp')) + ' "$@"\n')
        command.chmod(0o755)
        archive, digest = fixture.archive()
        result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--archive', str(archive),
                  '--sha256', digest, '--prefix', str(fixture.prefix)],
                  env={'PATH': str(tools) + os.pathsep + os.defpath}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list((fixture.prefix / 'bin').iterdir()), [])

    def test_pin_fails_closed_and_ruby_path_cannot_interpolate(self):
        spec = importlib.util.spec_from_file_location('pin', ROOT / 'scripts/homebrew-source.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        formula = (ROOT / 'Formula/zeropw.rb').read_text()
        head = 'head "https://github.com/telicity-ai/zeropw.git", branch: "main"'
        for text in [formula.replace(head, head.replace('head ', 'head  ')), formula + '\n' + head]:
            with self.assertRaises(ValueError):
                module.pin(text, '/tmp/source', 'a'*40)
        text = module.pin(formula, "/tmp/source#{raise 'unsafe'}/slash\\quote'", 'a'*40)
        self.assertIn("head '/tmp/source#{raise", text)
        self.assertIn('using: :git', text)
        self.assertNotIn('branch: "main"', text)
        # Ruby parses and evaluates the literal as data, with no interpolation.
        head_line = next(line.strip() for line in text.splitlines() if line.strip().startswith('head '))
        if not shutil.which('ruby'):
            self.fail('Homebrew source validation requires Ruby')
        result = subprocess.run(['ruby', '-e', 'def head(path, **args); puts path; end; ' + head_line],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/tmp/source#{raise 'unsafe'}/slash\\quote'")

    def test_identical_release_inputs_produce_identical_archives(self):
        fixture = self.fixture()
        bins = fixture.root / 'bins'
        bins.mkdir()
        for name in fixtures.BINS:
            (bins / name).write_bytes(b'#!/bin/sh\nexit 0\n')
        notices = fixture.root / 'notices.txt'
        notices.write_text('Synthetic dependency notices\n')
        archives = []
        for directory in ['one', 'two']:
            output = fixture.root / directory
            subprocess.run(['python3', str(ROOT / 'scripts/package-release.py'), '--version', 'v0.1.0',
                '--target', 'aarch64-apple-darwin', '--bin-dir', str(bins), '--out-dir', str(output),
                '--third-party-licenses', str(notices)], check=True, capture_output=True)
            archive = output / 'zeropw-v0.1.0-aarch64-apple-darwin.tar.gz'
            archives.append(archive.read_bytes())
            self.assertIn(hashlib.sha256(archives[-1]).hexdigest(),
                          pathlib.Path(str(archive) + '.sha256').read_text())
        self.assertEqual(archives[0], archives[1])
        self.assertEqual(archives[0][4:8], b'\0'*4)
