"""Run original Python black-box assertions against the native Rust products.

Only launch selection changes: admin/agent modules become Rust binaries, and
the example business CLI becomes the Rust democli. The original test cases,
synthetic endpoints, lifeline supervisor, leak scans, and assertions are kept.
Python is a test driver/oracle here, never a backend of a Rust product process.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import unittest
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--democli", required=True)
    parser.add_argument("case")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    binaries = {
        "zeropw.admin_cli": str(Path(options.admin).resolve(strict=True)),
        "zeropw.agent_cli": str(Path(options.agent).resolve(strict=True)),
    }
    calls = {module: 0 for module in binaries}
    original_popen = subprocess.Popen

    class NativePopen(original_popen):
        def __init__(self, args, *positional, **keywords):
            if isinstance(args, (list, tuple)):
                args = list(args)
                # This also rewrites the child command after lifeline.py's
                # separator, without replacing the Python supervisor itself.
                for offset in range(len(args) - 2):
                    if args[offset] == sys.executable and args[offset + 1] == "-m" and args[offset + 2] in binaries:
                        module = args[offset + 2]
                        args[offset : offset + 3] = [binaries[module]]
                        calls[module] += 1
                        break
            super().__init__(args, *positional, **keywords)

    subprocess.Popen = NativePopen
    from tests import test_cli_e2e

    test_cli_e2e.CliEndToEndTestCase.sample_cli = lambda self: Path(options.democli).resolve(strict=True)
    expected = set(binaries)
    if options.case.split(":", 1)[0] == "native_admin_contract":
        from tests import test_admin_cli

        def native_run_cli(self, *argv, stdin_bytes=None, state=None):
            full = ["--state-dir", str(state or self.state), *argv]
            proc = subprocess.run(
                [binaries["zeropw.admin_cli"], *full], input=stdin_bytes or b"",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=root, env=os.environ.copy(), timeout=120,
            )
            calls["zeropw.admin_cli"] += 1
            out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
            self.outputs.append((full, out, err))
            return proc.returncode, out, err

        test_admin_cli.AdminCliTestCase.run_cli = native_run_cli
        # These cases patch Python objects inside main/serve, not a black-box
        # contract. They require separately mapped native tests; they are NOT
        # counted as covered by this adapter.
        inprocess_only = {
            "test_serve_without_tools_fails_with_json",
            "test_serve_reports_signer_unavailable_when_missing",
            "test_serve_cancels_runs_and_closes_signer_sockets_revoked_by_another_process",
            "test_save_time_check_and_write_are_one_critical_section",
        }
        suite = unittest.TestSuite()
        selected = options.case.split(":", 1)[1] if ":" in options.case else None
        for cls in [test_admin_cli.AdminCliTestCase, test_admin_cli.TeamCliTestCase]:
            for name in sorted(cls.__dict__):
                if name.startswith("test_") and name not in inprocess_only and (selected is None or name == selected):
                    suite.addTest(cls(name))
        print(f"NATIVE_ADAPTER_UNMAPPED={sorted(inprocess_only)}", flush=True)
        expected = {"zeropw.admin_cli"}
    else:
        suite = unittest.defaultTestLoader.loadTestsFromName(options.case)
        if options.case.startswith("tests.test_agent_cli."):
            expected = {"zeropw.agent_cli"}
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    if result.skipped:
        # Unavailable real sshd must remain visible, never reported as verified.
        print(f"NATIVE_E2E_SKIPPED={len(result.skipped)}", flush=True)
    else:
        for module in expected:
            if not calls[module]:
                raise AssertionError(f"original test never launched native {module}")
    print(f"NATIVE_E2E_LAUNCHES={calls}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
