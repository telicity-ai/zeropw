#!/usr/bin/env python3
"""Run the Rust parity verification matrix in an isolated environment.

This driver executes repository code and tests. Run it only in the dedicated
verification VM described by ``docs/rust-completion.md``, never on a
coordinator, gateway, vault, signer, or credential-bearing host. The required
Python oracle is exactly CPython 3.12.14 and must be available as
``python3.12``.

Examples:
    python3.12 rust/verify.py --list
    python3.12 rust/verify.py --suite unit
    python3.12 rust/verify.py --suite all
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Sequence


SUITES = (
    "unit",
    "tls",
    "cli",
    "e2e",
    "data",
    "remaining0",
    "remaining1",
    "signer",
    "python",
)
ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "rust" / "Cargo.toml"
COMMAND_TIMEOUT_SECONDS = 60 * 60


def integration_manifest() -> dict[str, list[str]]:
    groups = {
        "tls": ["gateway_tls_parity", "gateway_replay_status_parity", "gateway"],
        "cli": [
            "runtime_parity_gaps",
            "admin_expanduser_parity",
            "cli_grant_limits_parity",
            "cli_parity",
            "agent_proxy_parity",
            "agent_help",
            "astra_cli_runtime_round2",
            "astra_cleanup_publication_order",
        ],
        "e2e": ["response_parity_gaps", "native_cli_e2e", "fake_upstream"],
        "data": [
            "python_numeric_comparison_parity",
            "ledger_float_parity",
            "team_envelope_parity_edges",
            "team_oracle",
            "team_fold",
            "team_snapshot_version_order_parity",
            "vault_public_parity",
        ],
    }
    all_targets = {path.stem for path in (ROOT / "rust" / "tests").glob("*.rs")}
    covered = {target for group in groups.values() for target in group}
    missing = sorted(covered - all_targets)
    if missing:
        raise AssertionError(f"integration targets missing from rust/tests: {missing!r}")
    remaining = sorted(all_targets - covered)
    groups["remaining0"] = remaining[::2]
    groups["remaining1"] = remaining[1::2]
    if sum(map(len, groups.values())) != len(all_targets):
        raise AssertionError("integration target groups overlap or omit a target")
    return groups


class Verification:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.environment = os.environ.copy()
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.environment["PYTHONUNBUFFERED"] = "1"

    def record(self, name: str, returncode: int) -> bool:
        print(f"AUDIT_STEP_END={name} exit={returncode}", flush=True)
        if returncode:
            self.failures.append(name)
            return False
        return True

    def run(
        self,
        name: str,
        command: Sequence[str | os.PathLike[str]],
        *,
        capture_output: bool = False,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        print(f"AUDIT_STEP_BEGIN={name}", flush=True)
        try:
            result = subprocess.run(
                [os.fspath(part) for part in command],
                cwd=ROOT,
                env=environment or self.environment,
                capture_output=capture_output,
                text=True,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            print(
                f"AUDIT_STEP_ERROR={name} timed out after {COMMAND_TIMEOUT_SECONDS}s",
                file=sys.stderr,
                flush=True,
            )
            stdout = (
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else exc.stdout or ""
            )
            stderr = (
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else exc.stderr or ""
            )
            result = subprocess.CompletedProcess(
                command,
                124,
                stdout,
                stderr,
            )
        except OSError as exc:
            print(f"AUDIT_STEP_ERROR={name} {exc}", file=sys.stderr, flush=True)
            result = subprocess.CompletedProcess(command, 127, "", str(exc))
        if capture_output:
            if result.stdout:
                print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)
            if result.stderr:
                print(
                    result.stderr,
                    end="" if result.stderr.endswith("\n") else "\n",
                    file=sys.stderr,
                    flush=True,
                )
        self.record(name, result.returncode)
        return result

    def check(self, name: str, condition: bool, error: str) -> bool:
        print(f"AUDIT_STEP_BEGIN={name}", flush=True)
        if not condition:
            print(f"AUDIT_STEP_ERROR={name} {error}", file=sys.stderr, flush=True)
        return self.record(name, int(not condition))

    def check_tools_and_source(self) -> str | None:
        head_result = self.run(
            "source-head", ["git", "rev-parse", "HEAD"], capture_output=True
        )
        initial_head = head_result.stdout.strip() if head_result.returncode == 0 else None
        status_result = self.run(
            "source-status", ["git", "status", "--porcelain"], capture_output=True
        )
        clean = status_result.returncode == 0 and not status_result.stdout.strip()
        self.check("source-clean", clean, "working tree is not clean")
        for name, command in (
            ("rustc-version", ["rustc", "--version"]),
            ("cargo-version", ["cargo", "--version"]),
            ("python-version", ["python3.12", "--version"]),
            (
                "python-exact-version",
                [
                    "python3.12",
                    "-c",
                    "import sys; assert sys.version_info[:3] == (3,12,14), sys.version",
                ],
            ),
            (
                "python-runtime-versions",
                [
                    "python3.12",
                    "-c",
                    "import ssl,unicodedata; print(ssl.OPENSSL_VERSION); print(unicodedata.unidata_version)",
                ],
            ),
            ("openssl-version", ["openssl", "version"]),
            ("ssh-version", ["ssh", "-V"]),
        ):
            self.run(name, command, capture_output=True)
        return initial_head

    def run_unit(self) -> None:
        self.run(
            "unit-fmt",
            ["cargo", "fmt", "--manifest-path", MANIFEST, "--", "--check"],
        )
        self.run(
            "unit-clippy",
            [
                "cargo",
                "clippy",
                "--locked",
                "--manifest-path",
                MANIFEST,
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        )
        self.run(
            "unit-library-and-binaries",
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                MANIFEST,
                "--lib",
                "--bins",
            ],
        )
        self.run_canonical_guard()

    def run_integrations(self, suite: str, targets: Sequence[str]) -> None:
        environment = self.environment.copy()
        environment["PARITY_SUITE"] = suite
        failed: list[str] = []
        for target in targets:
            result = self.run(
                f"{suite}:{target}",
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--manifest-path",
                    MANIFEST,
                    "--test",
                    target,
                    "--",
                    "--nocapture",
                ],
                environment=environment,
            )
            if result.returncode:
                failed.append(target)
        print(f"AUDIT_FAILED_{suite}={failed!r}", flush=True)

    def run_signer(self) -> None:
        self.run(
            "signer-ignored-serial",
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                MANIFEST,
                "--lib",
                "--",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ],
        )
        self.run(
            "signer-documentation",
            ["cargo", "test", "--locked", "--manifest-path", MANIFEST, "--doc"],
        )

    def run_python(self) -> None:
        self.run(
            "python-compileall",
            ["python3.12", "-m", "compileall", "-q", "zeropw", "tests", "harness"],
        )
        self.run(
            "python-reference-tests",
            [
                "python3.12",
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_*.py",
                "-v",
            ],
        )
        self.run(
            "python-harness-tests",
            [
                "python3.12",
                "-m",
                "unittest",
                "discover",
                "-s",
                "harness",
                "-p",
                "test_*.py",
                "-v",
            ],
        )

    def run_canonical_guard(self) -> None:
        name = "unit-canonical-guard"
        print(f"AUDIT_STEP_BEGIN={name}", flush=True)
        source = ROOT / "rust" / "src" / "gateway.rs"
        original: str | None = None
        returncode = 1
        try:
            build = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--manifest-path",
                    os.fspath(MANIFEST),
                    "--test",
                    "canonical_helpers",
                    "--no-run",
                    "--message-format=json",
                ],
                cwd=ROOT,
                env=self.environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
            if build.stderr:
                print(build.stderr, file=sys.stderr, flush=True)
            build.check_returncode()
            artifacts = [
                json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")
            ]
            binary = next(
                item["executable"]
                for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item["target"]["name"] == "canonical_helpers"
                and item.get("executable")
            )
            subprocess.run(
                [binary],
                cwd=ROOT,
                env=self.environment,
                check=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )

            original = source.read_text()
            assert "crate::pybase64::b64decode(s)" in original
            probes = [
                (
                    "no_base64_engine_decode_outside_pybase64",
                    original.replace(
                        "crate::pybase64::b64decode(s)",
                        "base64::engine::general_purpose::STANDARD.decode(s)",
                        1,
                    ),
                ),
                (
                    "no_number_to_string_outside_pyjson",
                    original
                    + "\n\nfn restored_float_render_bypass(n: &serde_json::Number) -> String { n.to_string() }\n",
                ),
            ]
            for test_name, mutated in probes:
                source.write_text(mutated)
                result = subprocess.run(
                    [binary, "--exact", test_name, "--nocapture"],
                    cwd=ROOT,
                    env=self.environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                )
                output = result.stdout + result.stderr
                assert result.returncode != 0 and "gateway.rs" in output, output
                print(f"AUDIT_GUARD_REJECTED={test_name}", flush=True)
            returncode = 0
        except Exception as exc:  # keep later independent verification steps running
            print(f"AUDIT_STEP_ERROR={name} {exc}", file=sys.stderr, flush=True)
        finally:
            if original is not None:
                source.write_text(original)
                if source.read_text() != original:
                    print(
                        f"AUDIT_STEP_ERROR={name} failed to restore {source}",
                        file=sys.stderr,
                        flush=True,
                    )
                    returncode = 1
        self.record(name, returncode)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the dynamically computed suite manifest without executing commands",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = integration_manifest()
    printable_manifest = {
        suite: manifest.get(suite, ["library/binaries and canonical guards"])
        for suite in SUITES
    }
    printable_manifest["signer"] = ["ignored library tests serially", "documentation tests"]
    printable_manifest["python"] = ["compileall", "reference unittest", "harness unittest"]
    print("AUDIT_INTEGRATION_MANIFEST=" + repr(manifest), flush=True)
    if args.list:
        print(json.dumps(printable_manifest, indent=2, sort_keys=False))
        return 0

    verification = Verification()
    initial_head = verification.check_tools_and_source()
    if verification.failures:
        print(
            "AUDIT_DEPENDENT_SUITES_SKIPPED=preflight failed",
            file=sys.stderr,
            flush=True,
        )
    else:
        selected = SUITES if args.suite == "all" else (args.suite,)
        for suite in selected:
            verification.environment["PARITY_SUITE"] = suite
            if suite == "unit":
                verification.run_unit()
            elif suite == "signer":
                verification.run_signer()
            elif suite == "python":
                verification.run_python()
            else:
                verification.run_integrations(suite, manifest[suite])

    final_head = verification.run(
        "final-source-head", ["git", "rev-parse", "HEAD"], capture_output=True
    )
    verification.check(
        "final-source-head-unchanged",
        initial_head is not None
        and final_head.returncode == 0
        and final_head.stdout.strip() == initial_head,
        "HEAD changed during verification or could not be read",
    )
    final_status = verification.run(
        "final-source-status", ["git", "status", "--porcelain"], capture_output=True
    )
    verification.check(
        "final-source-clean",
        final_status.returncode == 0 and not final_status.stdout.strip(),
        "working tree changed during verification or could not be read",
    )
    print(f"AUDIT_FAILED={verification.failures!r}", flush=True)
    return int(bool(verification.failures))


if __name__ == "__main__":
    raise SystemExit(main())
