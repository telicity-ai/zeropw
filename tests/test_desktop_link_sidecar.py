"""desktop/scripts/build-link-sidecar.py with a synthetic zeropw-link repository and a fake Go toolchain.

Nothing here runs Go or builds zeropw-link: a fake `go` answers `env`, `build` and `version -m`
from files the test writes, and records the environment each call saw. git is real, on a
throwaway repository.
"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'desktop/scripts/build-link-sidecar.py'
MODULE = 'github.com/telicity-ai/zeropw-link'
TARGET = 'aarch64-apple-darwin'

FAKE_GO = r'''#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
n=$(( $(cat "$here/count" 2>/dev/null || echo 0) + 1 )); echo $n > "$here/count"
env > "$here/env.$n"; printf '%s\n' "$@" > "$here/argv.$n"
case "$1 $2" in
  "env GOVERSION") cat "$here/goversion" ;;
  "env GOROOT") cat "$here/goroot" ;;
  "env GOMODCACHE") cat "$here/gomodcache" ;;
  "version -m") cat "$here/buildinfo" ;;
  build*)
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "-o" ] && out=$a; prev=$a; done
    cp "$here/binary" "$out" ;;
  *) echo "fake go: unexpected $*" >&2; exit 2 ;;
esac
'''


def macho(payload=b'synthetic daemon', minos=(13, 0)):
    """A thin arm64 Mach-O with LC_BUILD_VERSION (platform macOS, the given minos)."""
    command = struct.pack('<IIIIII', 0x32, 24, 1, (minos[0] << 16) | (minos[1] << 8), 26 << 16, 0)
    return struct.pack('<IIIIIIII', 0xfeedfacf, 0x0100000c, 0, 2, 1, len(command), 0, 0) + command + payload


def load():
    spec = importlib.util.spec_from_file_location('build_link_sidecar', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LinkSidecarTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = pathlib.Path(temp.name).resolve()
        self.module = load()
        # a zeropw-link repository: the pinned commit, then later work that must never be built
        self.repo = self.base / 'zeropw-link'
        (self.repo / 'cmd/zeropw-link').mkdir(parents=True)
        (self.repo / 'go.mod').write_text(f'module {MODULE}\n\ngo 1.27.3\n')
        (self.repo / 'go.sum').write_text('github.com/pion/ice/v4 v4.4.8 h1:synthetic-ice=\n'
                                          'github.com/pion/ice/v4 v4.4.8/go.mod h1:synthetic-ice-mod=\n'
                                          'github.com/Example/Upper v1.0.0 h1:synthetic-upper=\n')
        (self.repo / 'LICENSE').write_text('Synthetic zeropw-link MIT license\n')
        (self.repo / 'cmd/zeropw-link/main.go').write_text('package main // pinned\n')
        self.git('init', '-q')
        self.git('add', '-A')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'pinned')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        (self.repo / 'cmd/zeropw-link/main.go').write_text('package main // later\n')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-am', 'later')
        (self.repo / 'cmd/zeropw-link/main.go').write_text('package main // uncommitted\n')
        (self.repo / 'untracked.go').write_text('package main\n')
        self.record = self.base / 'zeropw-link.json'
        self.write_record()
        # the fake toolchain and its module cache
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        (self.tools / 'go').write_text(FAKE_GO)
        (self.tools / 'go').chmod(0o755)
        self.goroot = self.base / 'goroot'
        self.goroot.mkdir()
        (self.goroot / 'LICENSE').write_text('Synthetic Go BSD license\n')
        (self.goroot / 'PATENTS').write_text('Synthetic Go patent grant\n')
        self.modcache = self.base / 'gomodcache'
        ice = self.modcache / 'github.com/pion/ice/v4@v4.4.8'
        ice.mkdir(parents=True)
        (ice / 'LICENSE').write_text('Synthetic pion MIT license\n')
        (ice / 'agent.go').write_text('package ice\n')
        upper = self.modcache / 'github.com/!example/!upper@v1.0.0'
        upper.mkdir(parents=True)
        (upper / 'LICENSE.md').write_text('Mozilla Public License Version 2.0 (synthetic)\n')
        (self.tools / 'goversion').write_text('go1.27.3\n')
        (self.tools / 'goroot').write_text(str(self.goroot) + '\n')
        (self.tools / 'gomodcache').write_text(str(self.modcache) + '\n')
        self.out = self.base / 'out'
        self.buildinfo(['dep\tgithub.com/pion/ice/v4\tv4.4.8\th1:synthetic-ice=',
                        'dep\tgithub.com/Example/Upper\tv1.0.0\th1:synthetic-upper='])
        (self.tools / 'binary').write_bytes(macho())
        self.environ = {'PATH': str(self.tools) + os.pathsep + '/usr/bin:/bin', 'HOME': str(self.base / 'home'),
                        'LANG': 'C.UTF-8',
                        # none of these reaches go: proxies, flags, a workspace, credentials
                        'GOPROXY': 'https://proxy.example.invalid', 'GOFLAGS': '-mod=mod', 'GOWORK': str(self.base / 'go.work'),
                        'GONOSUMDB': '*', 'GOINSECURE': '*', 'AWS_SECRET_ACCESS_KEY': 'synthetic', 'CGO_ENABLED': '1'}

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True, text=True,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(self.base), 'GIT_CONFIG_NOSYSTEM': '1'}).stdout

    def write_record(self, **change):
        record = {'module': MODULE, 'commit': self.commit, 'go': 'go1.27.3', 'macos_minimum': '13.0', **change}
        self.record.write_text(json.dumps(record))

    def buildinfo(self, deps, version='go1.27.3', main=MODULE):
        (self.tools / 'buildinfo').write_text(
            f'{self.out}/bin/zeropw-link: {version}\n\tpath\t{main}/cmd/zeropw-link\n\tmod\t{main}\t(devel)\t\n'
            + ''.join(f'\t{line}\n' for line in deps) + '\tbuild\t-buildmode=exe\n')

    def build(self, *extra, target=TARGET):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.module.main(['--source', str(self.repo), '--target', target, '--out-dir', str(self.out),
                                     '--record', str(self.record), *extra], environ=self.environ)

    def refused(self, *fragments, **kwargs):
        with self.assertRaises(SystemExit) as raised:
            self.build(**kwargs)
        message = str(raised.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return message

    def go_calls(self):
        count = int((self.tools / 'count').read_text())
        calls = []
        for n in range(1, count + 1):
            argv = (self.tools / f'argv.{n}').read_text().splitlines()
            environment = dict(line.split('=', 1) for line in (self.tools / f'env.{n}').read_text().splitlines() if '=' in line)
            calls.append((argv, environment))
        return calls

    def test_builds_exactly_the_pinned_commit_offline(self):
        self.assertEqual(self.build(), 0)
        # the export is the pinned commit, not the later commit, the edit or the untracked file
        self.assertEqual((self.out / 'source/cmd/zeropw-link/main.go').read_text(), 'package main // pinned\n')
        self.assertFalse((self.out / 'source/untracked.go').exists())
        self.assertEqual((self.out / 'bin/zeropw-link').read_bytes(), macho())
        self.assertEqual((self.out / 'bin/zeropw-link').stat().st_mode & 0o777, 0o755)
        build = next((argv, environment) for argv, environment in self.go_calls() if argv[0] == 'build')
        argv, environment = build
        self.assertEqual(argv[:3], ['build', '-trimpath', '-buildvcs=false'])
        self.assertEqual(argv[3], f'-ldflags=-s -w -buildid= -X main.version={self.commit[:12]}')
        self.assertEqual(argv[-1], './cmd/zeropw-link')
        for key, value in {'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOFLAGS': '-mod=readonly', 'GOWORK': 'off', 'GOENV': 'off',
                           'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '0', 'GOOS': 'darwin', 'GOARCH': 'arm64',
                           'GONOSUMDB': '', 'GOINSECURE': ''}.items():
            self.assertEqual(environment.get(key), value, key)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', environment)
        build_txt = (self.out / 'BUILD.txt').read_text()
        self.assertIn(f'zeropw-link commit: {self.commit}', build_txt)
        self.assertIn('minimum macOS: 13.0', build_txt)
        self.assertIn('module: github.com/pion/ice/v4 v4.4.8 h1:synthetic-ice=', build_txt)

    def test_notices_cover_zeropw_link_go_and_every_module(self):
        self.build()
        text = (self.out / 'THIRD_PARTY_LICENSES.md').read_text()
        for fragment in (f'Target: {TARGET}.', f'zeropw-link commit: {self.commit}.', 'Go toolchain: go1.27.3.',
                         f'## {MODULE} {self.commit[:12]}', 'Synthetic zeropw-link MIT license',
                         '## Go standard library go1.27.3', 'Synthetic Go BSD license', 'Synthetic Go patent grant',
                         '## github.com/pion/ice/v4 v4.4.8', 'Synthetic pion MIT license',
                         # the module cache's case encoding; an MPL module is named for the source list
                         '## github.com/Example/Upper v1.0.0', 'Declared license: MPL-2.0 (from its license file)'):
            self.assertIn(fragment, text)
        self.assertNotIn(str(self.base), text)

    def test_a_module_without_a_license_stops_the_build_and_writes_nothing(self):
        (self.modcache / 'github.com/pion/ice/v4@v4.4.8/LICENSE').unlink()
        self.refused('no license file for: github.com/pion/ice/v4 v4.4.8')
        self.assertFalse((self.out / 'THIRD_PARTY_LICENSES.md').exists())

    def test_what_the_binary_lists_must_be_what_go_sum_pins(self):
        self.buildinfo(['dep\tgithub.com/pion/ice/v4\tv4.4.9\th1:other='])
        self.refused('modules not pinned by go.sum: github.com/pion/ice/v4 v4.4.9')
        self.assertFalse((self.out / 'bin/zeropw-link').exists())
        self.buildinfo(['dep\tgithub.com/pion/ice/v4\tv4.4.8\th1:synthetic-ice=', '=>\t../ice\t(devel)\t'])
        self.refused('replaced module')
        self.buildinfo([], main='example.com/other')
        self.refused('main module is example.com/other')

    def test_toolchain_minimum_macos_and_commit_must_match_the_record(self):
        (self.tools / 'goversion').write_text('go1.27.2\n')
        self.refused('Go is go1.27.2, the record needs go1.27.3')
        (self.tools / 'goversion').write_text('go1.27.3\n')
        (self.tools / 'binary').write_bytes(macho(minos=(11, 0)))
        self.refused('minimum macOS is 11.0, the record says 13.0')
        self.assertFalse((self.out / 'bin/zeropw-link').exists())
        (self.tools / 'binary').write_bytes(macho())
        self.write_record(commit='0' * 40)
        self.refused('has no commit ' + '0' * 40)
        self.write_record(commit='HEAD')
        self.refused('commit must be 40 lowercase hex digits')
        self.write_record(extra=True)
        self.refused('must hold module, commit, go, macos_minimum')

    def test_a_local_path_in_the_binary_is_refused(self):
        (self.tools / 'binary').write_bytes(macho(b'built in ' + str(self.repo).encode() + b'/link/node.go'))
        self.refused('the binary contains a local path: the zeropw-link checkout')
        (self.tools / 'binary').write_bytes(macho(b'/home/builder/go/pkg/mod/x.go'))
        self.refused('an account home')

    def test_linux_targets_build_without_a_macos_check(self):
        (self.tools / 'binary').write_bytes(b'\x7fELF synthetic')
        self.assertEqual(self.build(target='aarch64-unknown-linux-gnu'), 0)
        build = next(environment for argv, environment in self.go_calls() if argv[0] == 'build')
        self.assertEqual((build['GOOS'], build['GOARCH']), ('linux', 'arm64'))
        self.assertNotIn('minimum macOS', (self.out / 'BUILD.txt').read_text())

    def test_inputs_that_are_not_what_they_should_be_are_refused_before_building(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.build(target='armv7-unknown-linux-gnueabihf')
        self.out.mkdir()
        (self.out / 'precious').write_text('not ours')
        self.refused('is not empty and was not created by build-link-sidecar')
        self.assertTrue((self.out / 'precious').is_file())
        self.out = self.base / 'out2'
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()):
                self.module.main(['--source', str(self.base), '--target', TARGET, '--out-dir', str(self.out),
                                  '--record', str(self.record)], environ=self.environ)
        self.assertIn('is not a git checkout', str(raised.exception))
        # ZEROPW_LINK_SRC names the checkout when --source is not given
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.module.main(['--target', TARGET, '--out-dir', str(self.out), '--record', str(self.record)],
                                              environ=dict(self.environ, ZEROPW_LINK_SRC=str(self.repo))), 0)

    def test_the_committed_record_is_well_formed(self):
        record = self.module.read_record()
        self.assertEqual(record['module'], MODULE)
        self.assertEqual(record['go'], 'go1.27.3')
        self.assertEqual(self.module.escape_module('github.com/BurntSushi/toml'), 'github.com/!burnt!sushi/toml')


if __name__ == '__main__':
    unittest.main()
