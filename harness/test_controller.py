import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import controller as c


def item(status="READY", sha="a" * 40):
    return {"pr": 7, "head_sha": sha, "status": status, "ci": "passed", "draft": False}


def review(root, verdict="PASS", sha="a" * 40):
    value = {"repo": c.REPO, "pr": 7, "head_sha": sha, "base_sha": "b" * 40,
             "review": {"verdict": verdict, "summary": "review summary", "findings": []}}
    folder = root / ".zeropw-harness" / "reviews" / "7" / sha
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "result.json").write_text(json.dumps(value))
    return value


class ControllerTests(unittest.TestCase):
    def test_unchanged_is_quiet(self):
        with tempfile.TemporaryDirectory() as td, patch.object(c.zeropw_harness, "scan", return_value=[]):
            self.assertEqual(c.tick(Path(td)), {"changed": False, "events": []})

    def test_ready_pass_publishes_without_merge(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); record = review(root)
            with patch.object(c.zeropw_harness, "scan", return_value=[item()]), \
                 patch.object(c.zeropw_harness, "review", return_value=record), \
                 patch.object(c.zeropw_harness, "publish") as publish, \
                 patch.object(c.cloud_runner, "submit") as submit:
                result = c.tick(root)
            publish.assert_called_once_with(c.REPO, 7, "a" * 40, root.resolve())
            submit.assert_not_called()
            self.assertEqual(result["events"][0]["state"], "ready_for_acceptance")

    def test_revise_missing_config_is_resumable_from_reviewed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); record = review(root, "REVISE")
            with patch.object(c.zeropw_harness, "scan", return_value=[item()]), \
                 patch.object(c.zeropw_harness, "review", return_value=record), \
                 patch.object(c.zeropw_harness, "publish"), \
                 patch.object(c.cloud_runner, "load_config", side_effect=c.cloud_runner.CloudRunnerError("missing")):
                first = c.tick(root)
            self.assertEqual(first["events"][0]["state"], "fix_pending_configuration")
            resume = item("NEEDS_FIX"); resume.update(review_published=True, local_verdict="REVISE")
            with patch.object(c.zeropw_harness, "scan", return_value=[resume]), \
                 patch.object(c.cloud_runner, "load_config", return_value={}), \
                 patch.object(c.cloud_runner, "submit", return_value={"run_id": "r1"}) as submit:
                second = c.tick(root)
            submit.assert_called_once()
            self.assertEqual(second["events"][0]["state"], "fix_delegated")

    def test_pass_does_not_starve_later_ready_or_fix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); passed = review(root, "PASS")
            revise_sha = "c" * 40
            revised = review(root, "REVISE", revise_sha)
            revised["pr"] = 9
            old = root / ".zeropw-harness" / "reviews" / "7" / revise_sha
            new = root / ".zeropw-harness" / "reviews" / "9" / revise_sha
            new.parent.mkdir(parents=True, exist_ok=True); old.rename(new)
            (new / "result.json").write_text(json.dumps(revised))
            fix = {"pr": 9, "head_sha": revise_sha, "status": "NEEDS_FIX", "review_published": True,
                   "local_verdict": "REVISE"}
            ready = {"pr": 11, "head_sha": "d" * 40, "status": "READY"}
            ready_record = {**passed, "pr": 11, "head_sha": "d" * 40}
            with patch.object(c.zeropw_harness, "scan", return_value=[item("REVIEWED"), fix, ready]), \
                 patch.object(c.zeropw_harness, "review", return_value=ready_record) as run_review, \
                 patch.object(c.zeropw_harness, "publish"), \
                 patch.object(c.cloud_runner, "load_config", return_value={}), \
                 patch.object(c.cloud_runner, "submit", return_value={"run_id": "fix-9"}) as submit:
                result = c.tick(root)
            run_review.assert_called_once()
            submit.assert_called_once()
            self.assertEqual({e["state"] for e in result["events"]}, {"ready_for_acceptance", "fix_delegated"})

    def test_blocked_review_reports_explicit_reason(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); review(root, "BLOCKED")
            blocked = item("NEEDS_FIX"); blocked.update(review_published=True, local_verdict="BLOCKED")
            with patch.object(c.zeropw_harness, "scan", return_value=[blocked]):
                result = c.tick(root)
            self.assertIn("Opus BLOCKED", result["events"][0]["reason"])

    def test_attention_reason_change_is_new_event(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = c.Events(root); first.add("controller_attention", reason="first cause"); first.save()
            second = c.Events(root); second.add("controller_attention", reason="second cause"); second.save()
            third = c.Events(root); third.add("controller_attention", reason="second cause")
            self.assertEqual(len(first.new), 1)
            self.assertEqual(len(second.new), 1)
            self.assertEqual(third.new, [])

    def test_blocked_run_not_retried_and_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); runs = root / ".zeropw-harness" / "runs"; runs.mkdir(parents=True)
            (runs / "r.json").write_text(json.dumps({"run_id": "r", "status": "branch-raced", "pr": 7, "review_sha": "s"}))
            with patch.object(c.zeropw_harness, "scan", return_value=[]), patch.object(c.cloud_runner, "collect") as collect:
                first, second = c.tick(root), c.tick(root)
            collect.assert_not_called()
            self.assertTrue(first["changed"])
            self.assertEqual(second, {"changed": False, "events": []})

    def test_duplicate_fix_delegate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); review(root, "REVISE")
            with patch.object(c.zeropw_harness, "scan", return_value=[item("REVIEWED")]), \
                 patch.object(c.cloud_runner, "load_config", return_value={}), \
                 patch.object(c.cloud_runner, "submit", return_value={"run_id": "r", "duplicate": True}):
                first, second = c.tick(root), c.tick(root)
            self.assertTrue(first["events"][0]["duplicate"])
            self.assertEqual(second, {"changed": False, "events": []})

    def test_existing_lock_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); lock = root / ".zeropw-harness" / "controller.lock"
            lock.parent.mkdir(); lock.write_text("crashed")
            with self.assertRaises(c.ControllerBusy): c.tick(root)
            self.assertEqual(lock.read_text(), "crashed")

    def test_submitted_cloud_pending_is_quiet(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); runs = root / ".zeropw-harness" / "runs"; runs.mkdir(parents=True)
            (runs / "r.json").write_text(json.dumps({"run_id": "r", "status": "submitted"}))
            with patch.object(c.cloud_runner, "collect", return_value={"pending": True}), \
                 patch.object(c.zeropw_harness, "scan", return_value=[]):
                self.assertEqual(c.tick(root), {"changed": False, "events": []})


if __name__ == "__main__":
    unittest.main()
