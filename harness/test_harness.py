import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zeropw_harness as h

PROJECT = Path(__file__).resolve().parents[1]


def content_obj(text="x"):
    raw = text.encode()
    return {"type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode(), "sha": h.git_blob_sha(raw)}


class FakeRun:
    def __init__(self, routes): self.routes, self.calls = routes, []
    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        key = " ".join(argv)
        for needle, value in self.routes:
            if needle in key:
                return value(argv, kwargs) if callable(value) else json.dumps(value)
        raise AssertionError(key)


def pr(sha="head", state="open", cross=False, changed=1, draft=False):
    head_repo = "someone/fork" if cross else h.REPO
    body = h.READY_MARKER + f"\n{h.READY_SHA_PREFIX}{sha} -->"
    return {"number": 7, "state": state, "draft": draft, "title": "t", "body": body,
            "changed_files": changed, "head": {"sha": sha, "repo": {"full_name": head_repo}},
            "base": {"sha": "base", "ref": "main", "repo": {"full_name": h.REPO}}}


def check(status="completed", conclusion="success", ident=1, name="harness-tests"):
    return {"id": ident, "name": name, "status": status, "conclusion": conclusion,
            "app": {"slug": "github-actions"}}


def checks(*items):
    return [{"total_count": len(items), "check_runs": list(items)}]


def trusted_files(root):
    (root / "prompts").mkdir(parents=True)
    (root / "prompts" / "opus-review.txt").write_text("review")
    (root / "review.schema.json").write_text(json.dumps({"type": "object"}))


def install_workflow(root):
    target = root / h.CI_WORKFLOW
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((PROJECT / h.CI_WORKFLOW).read_bytes())


def workflow_tree(root=PROJECT):
    data = (root / h.CI_WORKFLOW).read_bytes()
    return {"truncated": False, "tree": [{"path": h.CI_WORKFLOW, "type": "blob", "mode": "100644", "sha": h.git_blob_sha(data)}]}


def stream(structured=None, assistant_model=h.MODEL_PREFIX, result_count=1, mixed_usage=False):
    structured = structured or {"verdict": "PASS", "summary": "s", "findings": []}
    events = [
        {"type": "system", "subtype": "init", "model": h.MODEL_PREFIX},
        {"type": "assistant", "parent_tool_use_id": None, "message": {"model": assistant_model}},
    ]
    usage = {h.MODEL_PREFIX: {}}
    if mixed_usage: usage["claude-haiku-4-5-20251001"] = {}
    events += [{"type": "result", "subtype": "success", "is_error": False,
                "structured_output": structured, "modelUsage": usage}] * result_count
    return "\n".join(json.dumps(e) for e in events) + "\n"


class HarnessTests(unittest.TestCase):
    def test_scan_pending_and_failed_ci(self):
        for item, expected in [(check("queued", None), "CI_PENDING"), (check(conclusion="failure"), "CI_FAILED")]:
            run = FakeRun([("pulls?state=open", [[pr()]]), ("git/trees", workflow_tree()), ("check-runs", checks(item))])
            self.assertEqual(h.scan(h.REPO, run)[0]["status"], expected)

    def test_scan_requires_head_bound_ready_marker(self):
        item = pr(); item["body"] = h.READY_MARKER + f"\n{h.READY_SHA_PREFIX}old -->"
        run = FakeRun([("pulls?state=open", [[item]]), ("git/trees", workflow_tree()), ("check-runs", checks(check()))])
        self.assertEqual(h.scan(h.REPO, run)[0]["status"], "NEEDS_FIX")

    def test_scan_untrusted_workflow_and_malformed_local_state_need_attention(self):
        wrong_tree = {"truncated": False, "tree": [{"path": h.CI_WORKFLOW, "type": "blob", "mode": "100644", "sha": "0" * 40}]}
        run = FakeRun([("pulls?state=open", [[pr()]]), ("git/trees", wrong_tree)])
        item = h.scan(h.REPO, run, root=PROJECT)[0]
        self.assertEqual((item["status"], item["ci"], item["attention"]), ("ATTENTION", "untrusted", True))
        self.assertEqual(item["reason"], "untrusted_ci_workflow")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); install_workflow(root)
            folder, result, _ = h._review_paths(root, 7, "head"); folder.mkdir(parents=True)
            result.write_text('{"review":null}')
            run = FakeRun([("pulls?state=open", [[pr()]]), ("git/trees", workflow_tree(root)),
                           ("check-runs", checks(check())), ("pulls/7/reviews", [[]])])
            item = h.scan(h.REPO, run, root=root)[0]
            self.assertEqual(item["status"], "ATTENTION")
            self.assertTrue(item["attention"])
            self.assertEqual(item["reason"], "malformed_local_review_state")

    def test_extra_workflow_shadowing_harness_tests_is_attention(self):
        tree = workflow_tree()
        tree["tree"].append({"path": ".github/workflows/shadow.yml", "type": "blob",
                             "mode": "100644", "sha": "1" * 40})
        run = FakeRun([("pulls?state=open", [[pr()]]), ("git/trees", tree)])
        item = h.scan(h.REPO, run, root=PROJECT)[0]
        self.assertEqual(item["status"], "ATTENTION")
        self.assertEqual(item["reason"], "untrusted_ci_workflow")
        self.assertFalse(any("check-runs" in " ".join(call[0]) for call in run.calls))

    def test_review_refuses_failed_or_pending_ci(self):
        for item, expected in [(check("queued", None), "pending"), (check(conclusion="failure"), "failed")]:
            run = FakeRun([("git/trees", workflow_tree()), ("check-runs", checks(item))])
            body = h.READY_MARKER + f"\n{h.READY_SHA_PREFIX}head -->"
            with tempfile.TemporaryDirectory() as td, patch.object(h, "build_snapshot", return_value={"head_sha": "head", "body": body, "draft": False}):
                install_workflow(Path(td))
                with self.assertRaisesRegex(h.HarnessError, expected):
                    h.review(h.REPO, 7, Path(td), run)

    def test_cross_repo_fails_closed_in_scan_and_snapshot(self):
        run = FakeRun([("pulls?state=open", [[pr(cross=True)]])])
        self.assertEqual(h.scan(h.REPO, run)[0]["status"], "UNSUPPORTED")
        run = FakeRun([("pulls/7", pr(cross=True))])
        with self.assertRaisesRegex(h.HarnessError, "cross-repository"):
            h.build_snapshot(h.REPO, 7, run)

    def test_truncated_content_rejected(self):
        bad = content_obj(); bad["truncated"] = True
        run = FakeRun([("contents/a.py", bad)])
        with self.assertRaisesRegex(h.HarnessError, "truncated"):
            h._content(h.REPO, "a.py", "head", run, {"a.py": {"type": "blob", "mode": "100644", "sha": bad["sha"]}})

    def test_base64_whitespace_allowed_but_symlink_rejected(self):
        obj = content_obj("hello")
        obj["content"] = obj["content"][:3] + "\n" + obj["content"][3:]
        run = FakeRun([("contents/a.py", obj)])
        tree = {"a.py": {"type": "blob", "mode": "100644", "sha": obj["sha"]}}
        self.assertEqual(h._content(h.REPO, "a.py", "head", run, tree)[0], b"hello")
        tree["a.py"]["mode"] = "120000"
        with self.assertRaisesRegex(h.HarnessError, "non-regular"):
            h._content(h.REPO, "a.py", "head", run, tree)

    def test_latest_trusted_actions_check_wins_and_other_checks_gate(self):
        old_failure = check(conclusion="failure", ident=1)
        new_success = check(conclusion="success", ident=2)
        self.assertEqual(h._ci_state([old_failure, new_success]), "passed")
        other_pending = check("queued", None, ident=3, name="lint")
        self.assertEqual(h._ci_state([old_failure, new_success, other_pending]), "pending")
        untrusted = check(ident=4); untrusted["app"] = {"slug": "other"}
        self.assertEqual(h._ci_state([untrusted]), "pending")

    def test_review_schema_rejects_duplicate_ids_bool_line_and_unknown_location(self):
        snapshot = {"files": [{"path": "a.py", "head": "one\ntwo", "base": "one"}], "trusted_docs": {}}
        finding = {"id": "F1", "severity": "high", "file": "a.py", "line": 2,
                   "description": "d", "required_change": "r"}
        base = {"verdict": "REVISE", "summary": "s", "findings": [finding]}
        self.assertEqual(h.validate_review(base, snapshot)["summary"], "s")
        duplicate = {**base, "findings": [finding, dict(finding)]}
        with self.assertRaisesRegex(h.HarnessError, "duplicate"):
            h.validate_review(duplicate, snapshot)
        bool_line = {**base, "findings": [{**finding, "line": True}]}
        with self.assertRaisesRegex(h.HarnessError, "values"):
            h.validate_review(bool_line, snapshot)
        unknown = {**base, "findings": [{**finding, "file": "missing.py"}]}
        with self.assertRaisesRegex(h.HarnessError, "outside"):
            h.validate_review(unknown, snapshot)

    def test_malformed_review_and_unexpected_model(self):
        with self.assertRaises(h.HarnessError): h.validate_review({"verdict": "PASS"})
        snapshot = {"x": 1}
        with tempfile.TemporaryDirectory() as td:
            trusted_files(Path(td))
            raw = stream(assistant_model="claude-sonnet-4")
            run = FakeRun([("claude -p --model", lambda _a, _k, raw=raw: raw)])
            with self.assertRaisesRegex(h.HarnessError, "unexpected"):
                h.invoke_claude(snapshot, run, Path(td), Path(td) / "raw.jsonl")

    def test_invoke_claude_has_no_tools_hooks_or_mcp(self):
        raw = stream(mixed_usage=True)
        run = FakeRun([("claude -p --model", lambda _a, _k: raw)])
        with tempfile.TemporaryDirectory() as td:
            trusted_files(Path(td))
            raw_path = Path(td) / "raw.jsonl"
            h.invoke_claude({"x": 1}, run, Path(td), raw_path)
            self.assertEqual(raw_path.stat().st_mode & 0o777, 0o600)
        argv, kwargs = run.calls[0]
        joined = " ".join(argv)
        for fragment in ("--tools ", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence", "disableAllHooks"):
            self.assertIn(fragment, joined)
        self.assertTrue(kwargs["cwd"].startswith("/"))
        self.assertIn("stream-json", argv)
        self.assertIn("--verbose", argv)

    def test_stream_missing_duplicate_result_and_truncated_json_rejected_after_raw_save(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td); trusted_files(folder)
            cases = [(stream(result_count=0), "got 0"), (stream(result_count=2), "got 2"), ('{"type":"system"\n', "malformed JSON")]
            for index, (raw, message) in enumerate(cases):
                raw_path = folder / f"raw-{index}.jsonl"
                run = FakeRun([("claude -p --model", lambda _a, _k, raw=raw: raw)])
                with self.assertRaisesRegex(h.HarnessError, message):
                    h.invoke_claude({"x": 1}, run, folder, raw_path)
                self.assertEqual(raw_path.read_text(), raw)

    def test_more_than_ten_opus_assistant_events_are_validated_without_display_limit_bug(self):
        events = [{"type": "system", "subtype": "init", "model": h.MODEL_PREFIX}]
        events += [{"type": "assistant", "parent_tool_use_id": None, "message": {"model": h.MODEL_PREFIX}} for _ in range(11)]
        events += [{"type": "result", "subtype": "success", "is_error": False,
                    "structured_output": {"verdict": "PASS", "summary": "s", "findings": []},
                    "modelUsage": {h.MODEL_PREFIX: {}}}]
        raw = "\n".join(json.dumps(e) for e in events)
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td); trusted_files(folder)
            run = FakeRun([("claude -p --model", lambda _a, _k: raw)])
            _, metadata = h.invoke_claude({"x": 1}, run, folder, folder / "raw.jsonl")
            self.assertEqual(metadata["assistant_event_count"], 11)
            self.assertEqual(len(metadata["verified_assistant_models"]), 10)

    def test_crash_lock_requires_manual_reconciliation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); folder, _, lock = h._review_paths(root, 7, "head")
            install_workflow(root)
            folder.mkdir(parents=True); lock.write_text("crashed")
            good = {"head_sha": "head", "body": h.READY_MARKER + f"\n{h.READY_SHA_PREFIX}head -->", "draft": False}
            check_pages = checks(check())
            with patch.object(h, "build_snapshot", return_value=good):
                with self.assertRaisesRegex(h.HarnessError, "manual reconciliation"):
                    h.review(h.REPO, 7, root, FakeRun([("git/trees", workflow_tree(root)), ("check-runs", check_pages)]))

    def _stored(self, root, sha="head"):
        install_workflow(root)
        folder, result, _ = h._review_paths(root, 7, sha); folder.mkdir(parents=True)
        snapshot = {"repo": h.REPO, "pr": 7, "head_sha": sha, "base_sha": "base", "files": [{"path": "a", "head": "x", "base": "x"}], "trusted_docs": {}}
        digest = h.snapshot_hash(snapshot)
        (folder / "input.json").write_text(json.dumps(snapshot))
        record = {"repo": h.REPO, "pr": 7, "head_sha": sha, "base_sha": "base", "input_sha256": digest,
                  "review": {"verdict": "REVISE", "summary": "summary", "findings": [{"id": "F1", "severity": "high", "file": "a", "line": 1, "description": "d", "required_change": "r"}]}}
        result.write_text(json.dumps(record)); return record

    def test_publish_stale_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self._stored(root)
            run = FakeRun([("pulls/7", pr("new"))])
            with self.assertRaisesRegex(h.HarnessError, "stale"):
                h.publish(h.REPO, 7, "head", root, run)

    def test_duplicate_publish_does_not_post(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); record = self._stored(root)
            body = h.render_review(record)
            remote = {"body": body, "commit_id": "head", "user": {"login": "handlecusion"}}
            run = FakeRun([("pulls/7/reviews", [[remote]]), ("git/trees", workflow_tree(root)), ("check-runs", checks(check())), ("pulls/7", pr())])
            result = h.publish(h.REPO, 7, "head", root, run)
            self.assertTrue(result["duplicate"])
            self.assertFalse(any("-X POST" in " ".join(c[0]) for c in run.calls))

    def test_publish_comment_preserves_severity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self._stored(root)
            run = FakeRun([("-X POST", {"id": 9}), ("pulls/7/reviews", [[]]), ("git/trees", workflow_tree(root)), ("check-runs", checks(check())), ("pulls/7", pr())])
            self.assertTrue(h.publish(h.REPO, 7, "head", root, run)["published"])
            post = next(c for c in run.calls if "-X" in c[0])
            self.assertIn("HIGH", " ".join(post[0]))
            self.assertIn("event=COMMENT", post[0])


if __name__ == "__main__": unittest.main()
