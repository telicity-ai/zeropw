"""Run original Python black-box assertions against the native Rust products.

Only launch selection changes: admin/agent modules become Rust binaries, and
the example business CLI becomes the Rust democli. The original test cases,
synthetic endpoints, lifeline supervisor, leak scans, and assertions are kept.
Python is a test driver/oracle here, never a backend of a Rust product process.
"""

from __future__ import annotations

import argparse
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
    suite = unittest.defaultTestLoader.loadTestsFromName(options.case)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    if result.skipped:
        # Unavailable real sshd must remain visible, never reported as verified.
        print(f"NATIVE_E2E_SKIPPED={len(result.skipped)}", flush=True)
    else:
        for module, count in calls.items():
            if not count:
                raise AssertionError(f"original test never launched native {module}")
    print(f"NATIVE_E2E_LAUNCHES={calls}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
