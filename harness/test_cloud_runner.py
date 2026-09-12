import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cloud_runner as c


class FakeRun:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        joined = " ".join(argv)
        for needle, value in self.routes:
            if needle in joined:
                return value(argv, kwargs) if callable(value) else value
        raise AssertionError(joined)


def setup_root(folder):
    root = Path(folder)
    (root / ".zeropw-harness" / "runs").mkdir(parents=True)
    (root / ".zeropw-harness" / "config.json").write_text(json.dumps({
        "repo": c.REPO, "cloud_environment_id": "env-1",
        "worker_mode": "codex-cloud-default", "cloud_default_model_accepted": True,
    }))
    prompt = root / "prompt.txt"
    prompt.write_text("make a safe change")
    return root, prompt


class CloudRunnerTests(unittest.TestCase):
    def test_cloud_list_cursor_and_environment_binding(self):
        run = FakeRun([
            ("--cursor next", json.dumps({"tasks": [{"id": "wanted", "environment_id": "env-1"}], "cursor": None})),
            ("cloud list --env env-1 --json --limit 20", json.dumps({"tasks": [], "cursor": "next"})),
        ])
        self.assertEqual(c._find_task("wanted", "env-1", run)["id"], "wanted")
        mismatch = FakeRun([("cloud list", json.dumps({
            "tasks": [{"id": "wanted", "environment_id": "other"}], "cursor": None}))])
        with self.assertRaisesRegex(c.CloudRunnerError, "environment mismatch"):
            c._find_task("wanted", "env-1", mismatch)

    def test_uncertain_submit_blocks_identical_redispatch(self):
        with tempfile.TemporaryDirectory() as td:
            root, prompt = setup_root(td)
            def fail(*_):
                raise c.CloudRunnerError("transport lost")
            run = FakeRun([("ls-remote", "a" * 40 + "\trefs/heads/main\n"),
                           ("cloud exec", fail)])
            with patch.object(c.uuid, "uuid4", return_value="00000000-0000-0000-0000-000000000006"):
                with self.assertRaisesRegex(c.CloudRunnerError, "transport lost"):
                    c.submit(root, prompt, "main", run=run)
            before = sum("cloud exec" in " ".join(call[0]) for call in run.calls)
            duplicate = c.submit(root, prompt, "main", run=run)
            after = sum("cloud exec" in " ".join(call[0]) for call in run.calls)
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual((before, after), (1, 1))

    def test_unparseable_submit_output_is_uncertain(self):
        with tempfile.TemporaryDirectory() as td:
            root, prompt = setup_root(td)
            run_id = "00000000-0000-0000-0000-000000000007"
            run = FakeRun([("ls-remote", "a" * 40 + "\trefs/heads/main\n"),
                           ("cloud exec", "accepted without identifier")])
            with patch.object(c.uuid, "uuid4", return_value=run_id):
                with self.assertRaisesRegex(c.CloudRunnerError, "task URL"):
                    c.submit(root, prompt, "main", run=run)
            saved = json.loads((root / ".zeropw-harness" / "runs" / f"{run_id}.json").read_text())
            self.assertEqual(saved["status"], "submit-uncertain")
            self.assertIn("accepted without identifier", saved["task_output"])

    def test_unknown_collect(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(c.CloudRunnerError, "unknown run"):
                c.collect(Path(td), "00000000-0000-0000-0000-000000000000", FakeRun([]))

    def test_pending_task_does_not_fetch_diff(self):
        with tempfile.TemporaryDirectory() as td:
            root, _ = setup_root(td)
            run_id = "00000000-0000-0000-0000-000000000001"
            (root / ".zeropw-harness" / "runs" / f"{run_id}.json").write_text(json.dumps({
                "run_id": run_id, "status": "submitted", "task_id": "task-1", "environment": "env-1"
            }))
            run = FakeRun([("cloud list", json.dumps({"items": [{"id": "task-1"}]})),
                           ("cloud status", "[RUNNING] work")])
            self.assertTrue(c.collect(root, run_id, run)["pending"])
            self.assertFalse(any("cloud diff" in " ".join(x[0]) for x in run.calls))

    def test_missing_task_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root, _ = setup_root(td)
            run_id = "00000000-0000-0000-0000-000000000002"
            (root / ".zeropw-harness" / "runs" / f"{run_id}.json").write_text(json.dumps({"status": "submitted"}))
            with self.assertRaisesRegex(c.CloudRunnerError, "confirmed cloud task id"):
                c.collect(root, run_id, FakeRun([]))

    def test_submit_branch_race_is_journaled(self):
        with tempfile.TemporaryDirectory() as td:
            root, prompt = setup_root(td)
            heads = iter(["a" * 40, "b" * 40])
            run = FakeRun([("ls-remote", lambda *_: next(heads) + "\trefs/heads/main\n"),
                           ("cloud exec", "https://chatgpt.com/codex/tasks/task-1")])
            with patch.object(c.uuid, "uuid4", return_value="00000000-0000-0000-0000-000000000003"):
                with self.assertRaisesRegex(c.CloudRunnerError, "moved"):
                    c.submit(root, prompt, "main", run=run)
            saved = json.loads((root / ".zeropw-harness/runs/00000000-0000-0000-0000-000000000003.json").read_text())
            self.assertEqual(saved["status"], "branch-raced")

    def test_unsafe_patch_paths_and_modes(self):
        bad = ["diff --git a/../x b/../x\n", "diff --git a/x b/x\nnew file mode 120000\n"]
        for value in bad:
            with self.assertRaises(c.CloudRunnerError):
                c.validate_patch(value)

    def test_duplicate_collect_has_no_commands(self):
        with tempfile.TemporaryDirectory() as td:
            root, _ = setup_root(td)
            run_id = "00000000-0000-0000-0000-000000000004"
            record = {"run_id": run_id, "status": "published", "commit_sha": "a" * 40}
            (root / ".zeropw-harness" / "runs" / f"{run_id}.json").write_text(json.dumps(record))
            run = FakeRun([])
            self.assertTrue(c.collect(root, run_id, run)["duplicate"])
            self.assertEqual(run.calls, [])

    def test_collect_reconciles_existing_published_branch(self):
        with tempfile.TemporaryDirectory() as td:
            root, _ = setup_root(td)
            run_id = "00000000-0000-0000-0000-000000000005"
            head = "b" * 40
            record = {"run_id": run_id, "status": "submitted", "task_id": "task-5",
                      "environment": "env-1", "branch": "main", "base_sha": "a" * 40, "pr": None}
            (root / ".zeropw-harness" / "runs" / f"{run_id}.json").write_text(json.dumps(record))
            branch = f"harness/cloud-{run_id}"
            pr = {"number": 9, "head": {"sha": head},
                  "body": c.READY + "\n" + c.READY_SHA.format(sha=head) +
                          f"\n<!-- zeropw-run:{run_id} -->"}
            run = FakeRun([("cloud list", json.dumps({"items": [{"id": "task-5"}]})),
                           ("cloud status", "[READY] done"),
                           (f"refs/heads/{branch}", f"{head}\trefs/heads/{branch}\n"),
                           ("pulls?state=open", json.dumps([pr]))])
            result = c.collect(root, run_id, run)
            self.assertTrue(result["reconciled"])
            self.assertFalse(any("cloud diff" in " ".join(x[0]) for x in run.calls))

    def test_fix_stale_review_sha(self):
        with tempfile.TemporaryDirectory() as td:
            root, prompt = setup_root(td)
            pr = {"state": "open", "base": {"ref": "main", "repo": {"full_name": c.REPO}},
                  "head": {"sha": "new", "ref": "fix", "repo": {"full_name": c.REPO}}}
            run = FakeRun([("pulls/7", json.dumps(pr))])
            with self.assertRaisesRegex(c.CloudRunnerError, "stale"):
                c.submit(root, prompt, "main", 7, "old", run)


if __name__ == "__main__":
    unittest.main()
