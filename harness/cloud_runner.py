#!/usr/bin/env python3
"""Submit Codex Cloud work and publish retrieved patches without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable

REPO = "handlecusion/zeropw"
READY = "<!-- zeropw:ready-for-review -->"
READY_SHA = "<!-- zeropw-ready-sha:{sha} -->"
MAX_PATCH_BYTES = 2_000_000


class CloudRunnerError(RuntimeError):
    pass


class ApprovalRequired(CloudRunnerError):
    def __init__(self, paths: list[str]):
        super().__init__("Cloud patch changes trusted control-plane files")
        self.paths = paths


class CommandRunner:
    def __call__(self, argv: list[str], *, cwd: str | None = None,
                 env: dict[str, str] | None = None) -> str:
        safe_env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")}
        if env:
            safe_env.update(env)
        try:
            proc = subprocess.run(argv, cwd=cwd, env=safe_env, text=True, timeout=600,
                                  capture_output=True, check=False)
        except subprocess.TimeoutExpired as exc:
            raise CloudRunnerError(f"command timed out ({argv[0]})") from exc
        if proc.returncode:
            raise CloudRunnerError(f"command failed ({argv[0]}): {proc.stderr.strip()[:500]}")
        return proc.stdout


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _json_dict(raw: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CloudRunnerError(f"malformed {context}") from exc
    if not isinstance(value, dict):
        raise CloudRunnerError(f"malformed {context}: expected object")
    return value


def _read_json_dict(path: Path, context: str) -> dict[str, Any]:
    try:
        return _json_dict(path.read_text(), context)
    except OSError as exc:
        raise CloudRunnerError(f"missing or unreadable {context}") from exc


def _run_record(path: Path, context: str = "run ledger") -> dict[str, Any]:
    value = _read_json_dict(path, context)
    if not isinstance(value.get("status"), str):
        raise CloudRunnerError(f"malformed {context}: status must be a string")
    typed = {"run_id": str, "repo": str, "environment": str, "branch": str,
             "base_sha": str, "task_id": str, "pr": int, "review_sha": str}
    for key, expected in typed.items():
        if key in value and value[key] is not None and not isinstance(value[key], expected):
            raise CloudRunnerError(f"malformed {context}: invalid {key}")
    return value


def load_config(root: Path) -> dict[str, Any]:
    path = root / ".zeropw-harness" / "config.json"
    value = _read_json_dict(path, "cloud config")
    required = {
        "repo": REPO,
        "worker_mode": "codex-cloud-default",
        "cloud_default_model_accepted": True,
    }
    if any(value.get(k) != v for k, v in required.items()):
        raise CloudRunnerError("cloud config is not accepted")
    if not isinstance(value.get("cloud_environment_id"), str) or not value["cloud_environment_id"]:
        raise CloudRunnerError("cloud_environment_id is required")
    return value


def _remote_head(branch: str, run: Callable[..., str]) -> str:
    raw = run(["git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"])
    rows = [line.split() for line in raw.splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r"[0-9a-f]{40}", rows[0][0]):
        raise CloudRunnerError("remote branch is missing or ambiguous")
    return rows[0][0]


def _remote_head_optional(branch: str, run: Callable[..., str]) -> str | None:
    raw = run(["git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"])
    rows = [line.split() for line in raw.splitlines() if line.strip()]
    if not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r"[0-9a-f]{40}", rows[0][0]):
        raise CloudRunnerError("remote branch is ambiguous")
    return rows[0][0]


def _run_path(root: Path, run_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise CloudRunnerError("invalid run id")
    return root / ".zeropw-harness" / "runs" / f"{run_id}.json"


def _task_id(output: str) -> tuple[str, str]:
    urls = re.findall(r"https://[^\s]+", output)
    if len(urls) != 1:
        raise CloudRunnerError("cloud submit did not return exactly one task URL")
    url = urls[0].rstrip(".,;)")
    match = re.search(r"/([A-Za-z0-9_-]+)$", url)
    if not match:
        raise CloudRunnerError("cloud task id missing from URL")
    return match.group(1), url


def _pr_info(number: int, run: Callable[..., str]) -> dict[str, Any]:
    raw = run(["gh", "api", f"repos/{REPO}/pulls/{number}"])
    pr = _json_dict(raw, "PR response")
    if (not isinstance(pr.get("head"), dict) or not isinstance(pr.get("base"), dict) or
            not isinstance(pr["head"].get("repo"), dict) or
            not isinstance(pr["base"].get("repo"), dict)):
        raise CloudRunnerError("malformed PR response: invalid head/base")
    if (pr.get("state") != "open" or pr.get("base", {}).get("ref") != "main" or
            pr.get("head", {}).get("repo", {}).get("full_name") != REPO or
            pr.get("base", {}).get("repo", {}).get("full_name") != REPO):
        raise CloudRunnerError("fix target must be an open same-repository PR based on main")
    return pr


def _pages(raw: str, context: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CloudRunnerError(f"malformed {context}") from exc
    if isinstance(value, list) and value and all(isinstance(x, list) for x in value):
        flattened = [item for page in value for item in page]
        if all(isinstance(item, dict) for item in flattened):
            return flattened
        raise CloudRunnerError(f"malformed {context}: expected objects")
    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            return value
        raise CloudRunnerError(f"malformed {context}: expected objects")
    raise CloudRunnerError(f"malformed {context}")


def _fingerprint(fields: dict[str, Any]) -> str:
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def submit(root: Path, prompt_file: Path, branch: str, pr_number: int | None = None,
           review_sha: str | None = None, run: Callable[..., str] = CommandRunner()) -> dict[str, Any]:
    config = load_config(root)
    root_resolved = root.resolve()
    try:
        resolved_prompt = (root_resolved / prompt_file).resolve(strict=True) if not prompt_file.is_absolute() else prompt_file.resolve(strict=True)
    except OSError as exc:
        raise CloudRunnerError("trusted prompt file is unavailable") from exc
    if not resolved_prompt.is_relative_to(root_resolved):
        raise CloudRunnerError("prompt file must be inside the repository")
    try:
        prompt = resolved_prompt.read_text()
    except OSError as exc:
        raise CloudRunnerError("trusted prompt file is unavailable") from exc
    if pr_number is not None:
        if not review_sha:
            raise CloudRunnerError("--review-sha is required for a fix")
        pr = _pr_info(pr_number, run)
        branch = pr["head"]["ref"]
        if pr["head"]["sha"] != review_sha:
            raise CloudRunnerError("fix review SHA is stale")
        result_path = root / ".zeropw-harness" / "reviews" / str(pr_number) / review_sha / "result.json"
        local_review = _read_json_dict(result_path, "trusted local REVISE review")
        if not isinstance(local_review.get("review"), dict):
            raise CloudRunnerError("trusted local REVISE review binding mismatch")
        if (local_review.get("repo") != REPO or local_review.get("pr") != pr_number or
                local_review.get("head_sha") != review_sha or
                local_review.get("review", {}).get("verdict") != "REVISE"):
            raise CloudRunnerError("trusted local REVISE review binding mismatch")
        reviews = _pages(run(["gh", "api", f"repos/{REPO}/pulls/{pr_number}/reviews?per_page=100",
                              "--paginate", "--slurp"]), "PR reviews")
        marker = f"<!-- zeropw-opus:{review_sha} -->"
        verdict_line = "ZeroPW Opus verdict: **REVISE**"
        if not any(isinstance(x.get("user"), dict) and
                   x["user"].get("login") == "handlecusion" and
                   x.get("commit_id") == review_sha and marker in (x.get("body") or "") and
                   verdict_line in (x.get("body") or "") for x in reviews):
            raise CloudRunnerError("published REVISE review for current head is required")
        prior = list((root / ".zeropw-harness" / "runs").glob("*.json"))
        records = [_run_record(p, f"run ledger {p.name}") for p in prior]
        if any(x.get("pr") == pr_number and x.get("status") in
               {"prepared", "submitting", "submit-uncertain", "submitted", "branch-raced", "needs-approval"}
               for x in records):
            raise CloudRunnerError("a fix run for this PR is already active or uncertain")
        rounds = sum(1 for x in records if x.get("pr") == pr_number)
        if rounds >= 3:
            raise CloudRunnerError("automatic fix round limit reached")
    base = _remote_head(branch, run)
    if pr_number is not None and base != review_sha:
        raise CloudRunnerError("fix branch base no longer matches the reviewed SHA")
    identity = {"repo": REPO, "environment": config["cloud_environment_id"], "branch": branch,
                "base_sha": base, "pr": pr_number, "review_sha": review_sha,
                "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                "worker_mode": config["worker_mode"],
                "cloud_default_model_accepted": config["cloud_default_model_accepted"]}
    fingerprint = _fingerprint(identity)
    for prior_path in (root / ".zeropw-harness" / "runs").glob("*.json"):
        prior = _run_record(prior_path, f"run ledger {prior_path.name}")
        if prior.get("input_fingerprint") == fingerprint and prior.get("status") in {
                "prepared", "submitting", "submit-uncertain", "submitted", "branch-raced", "needs-approval"}:
            return {**prior, "duplicate": True}
    run_id = str(uuid.uuid4())
    path = _run_path(root, run_id)
    query = (f"ZeroPW trusted run {run_id}. Follow the trusted instructions included inline below. "
             "Never expose product credentials or secret values.\n\n" + prompt)
    record = {"run_id": run_id, "repo": REPO, "environment": config["cloud_environment_id"],
              "branch": branch, "base_sha": base, "pr": pr_number, "review_sha": review_sha,
              "prompt_sha256": identity["prompt_sha256"], "input_fingerprint": fingerprint,
              "worker_mode": identity["worker_mode"],
              "cloud_default_model_accepted": identity["cloud_default_model_accepted"],
              "observed_cloud_model_id": "unknown",
              "status": "prepared"}
    _atomic(path, record)
    record["status"] = "submitting"
    _atomic(path, record)
    try:
        output = run(["codex", "cloud", "exec", "--env", config["cloud_environment_id"],
                      "--branch", branch, "--attempts", "1", query])
    except Exception:
        record["status"] = "submit-uncertain"
        _atomic(path, record)
        raise
    try:
        task_id, task_url = _task_id(output)
        record.update(task_id=task_id, task_url=task_url, task_output=output[:2000])
    except CloudRunnerError:
        candidates = [value.rstrip(".,;)") for value in re.findall(r"https://[^\s]+", output)]
        record.update(status="submit-uncertain", task_output=output[:2000],
                      task_url_candidates=candidates[:10])
        _atomic(path, record)
        raise
    if _remote_head(branch, run) != base:
        record["status"] = "branch-raced"
        _atomic(path, record)
        raise CloudRunnerError("remote branch moved during submit")
    record.update(status="submitted")
    _atomic(path, record)
    return record


def _find_task(task_id: str, environment: str, run: Callable[..., str]) -> dict[str, Any] | None:
    cursor: str | None = None
    seen: set[str] = set()
    while True:
        argv = ["codex", "cloud", "list", "--env", environment, "--json", "--limit", "20"]
        if cursor:
            argv += ["--cursor", cursor]
        try:
            page = json.loads(run(argv))
        except (TypeError, json.JSONDecodeError) as exc:
            raise CloudRunnerError("malformed cloud task list") from exc
        if not isinstance(page, (dict, list)):
            raise CloudRunnerError("malformed cloud task list: expected object or list")
        items = page if isinstance(page, list) else page.get("tasks", page.get("items", []))
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise CloudRunnerError("malformed cloud task items")
        for item in items:
            if str(item.get("id")) == task_id:
                item_env = item.get("environment_id")
                if not isinstance(item_env, str) or not item_env:
                    raise CloudRunnerError("cloud task environment_id is unavailable")
                if item_env != environment:
                    raise CloudRunnerError("cloud task environment mismatch")
                return item
        cursor = None if isinstance(page, list) else page.get("cursor", page.get("next_cursor", page.get("nextCursor")))
        if not cursor:
            return None
        if cursor in seen:
            raise CloudRunnerError("cloud list cursor loop")
        seen.add(cursor)


def validate_patch(patch: str) -> None:
    raw = patch.encode()
    if not raw or len(raw) > MAX_PATCH_BYTES or b"\0" in raw:
        raise CloudRunnerError("empty, binary, or oversized patch")
    if (re.search(r"^GIT binary patch$", patch, re.MULTILINE) or
            re.search(r"^(?:literal|delta) \d+$", patch, re.MULTILINE)):
        raise CloudRunnerError("Git binary patches are forbidden")
    if re.search(r"^(?:new|old)(?: file)? mode (?:120000|160000)$", patch, re.MULTILINE):
        raise CloudRunnerError("symlink and gitlink patches are forbidden")
    if re.search(r'^diff --git (?:"|a/[^\n]*\s+")', patch, re.MULTILINE):
        raise CloudRunnerError("quoted Git diff paths are unsupported")
    paths = re.findall(r"^diff --git a/(.+?) b/(.+)$", patch, re.MULTILINE)
    if not paths:
        raise CloudRunnerError("patch has no file paths")
    for pair in paths:
        for value in pair:
            path = PurePosixPath(value)
            if value.startswith("/") or ".." in path.parts or ".git" in path.parts:
                raise CloudRunnerError("unsafe patch path")


def _changed_paths_from_diff_tree(raw: str) -> list[str]:
    """Parse `git diff-tree --name-status -z`; -z disables Git path quoting."""
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    paths: list[str] = []
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not re.fullmatch(r"[ACDMRTUXB](?:\d{1,3})?", status):
            raise CloudRunnerError("unparseable changed-path status")
        count = 2 if status[0] in {"R", "C"} else 1
        if index + count > len(fields):
            raise CloudRunnerError("truncated changed-path record")
        paths.extend(fields[index:index + count])
        index += count
    if any(not path or path.startswith("/") or ".." in PurePosixPath(path).parts or
           ".git" in PurePosixPath(path).parts for path in paths):
        raise CloudRunnerError("unsafe path in applied tree difference")
    return sorted(set(paths))


def _control_paths(paths: list[str]) -> list[str]:
    protected_docs = {"docs/harness.md", "docs/product-intent.md", "docs/security-design.md"}
    protected_docs_folded = {path.casefold() for path in protected_docs}
    return [path for path in paths if path.casefold() == "agents.md" or
            path.casefold() in protected_docs_folded or
            path.casefold().startswith(".github/") or
            path.casefold().startswith("harness/")]


def _materialize(record: dict[str, Any], patch: str, branch: str,
                 run: Callable[..., str]) -> str:
    validate_patch(patch)
    origin = run(["git", "remote", "get-url", "origin"]).strip()
    allowed_origins = {"https://github.com/handlecusion/zeropw.git",
                       "git@github.com:handlecusion/zeropw.git"}
    if origin not in allowed_origins:
        raise CloudRunnerError("origin URL is not the exact trusted repository")
    with tempfile.TemporaryDirectory(prefix="zeropw-cloud-") as folder:
        bare = Path(folder) / "repo.git"
        index = str(Path(folder) / "index")
        run(["git", "init", "--bare", str(bare)])
        run(["git", "--git-dir", str(bare), "fetch", "--no-tags", origin, record["base_sha"]])
        touched = {item for pair in re.findall(r"^diff --git a/(.+?) b/(.+)$", patch, re.MULTILINE)
                   for item in pair}
        tree_rows = run(["git", "--git-dir", str(bare), "ls-tree", "-r", record["base_sha"]])
        for row in tree_rows.splitlines():
            match = re.match(r"(\d+)\s+\w+\s+[0-9a-f]+\t(.+)$", row)
            if match and match.group(2) in touched and match.group(1) in {"120000", "160000"}:
                raise CloudRunnerError("patch touches an existing symlink or gitlink")
        env = {"GIT_INDEX_FILE": index, "GIT_AUTHOR_NAME": "ZeroPW Cloud Harness",
               "GIT_AUTHOR_EMAIL": "noreply@zeropw.local",
               "GIT_COMMITTER_NAME": "ZeroPW Cloud Harness",
               "GIT_COMMITTER_EMAIL": "noreply@zeropw.local"}
        run(["git", "--git-dir", str(bare), "read-tree", record["base_sha"]], env=env)
        patch_path = Path(folder) / "change.patch"
        patch_path.write_text(patch)
        run(["git", "--git-dir", str(bare), "apply", "--cached", str(patch_path)], env=env)
        tree = run(["git", "--git-dir", str(bare), "write-tree"], env=env).strip()
        result_rows = run(["git", "--git-dir", str(bare), "ls-tree", "-rz", tree])
        for row in result_rows.split("\0"):
            if not row:
                continue
            match = re.fullmatch(r"(\d+)\s+\w+\s+[0-9a-f]+\t(.+)", row, re.DOTALL)
            if not match:
                raise CloudRunnerError("unparseable result tree")
            mode, result_path = match.groups()
            parts = PurePosixPath(result_path).parts
            if mode in {"120000", "160000"} or result_path.startswith("/") or ".." in parts or ".git" in parts:
                raise CloudRunnerError("unsafe path or mode in result tree")
        changed_raw = run(["git", "--git-dir", str(bare), "diff-tree", "--no-commit-id",
                           "--name-status", "-r", "-z", record["base_sha"], tree])
        changed_paths = _changed_paths_from_diff_tree(changed_raw)
        protected = _control_paths(changed_paths)
        if protected:
            raise ApprovalRequired(protected)
        commit = run(["git", "--git-dir", str(bare), "commit-tree", tree, "-p", record["base_sha"],
                      "-m", f"Codex Cloud run {record['run_id']}"], env=env).strip()
        run(["git", "--git-dir", str(bare), "push", origin,
             f"{commit}:refs/heads/{branch}"])
        return commit


def collect(root: Path, run_id: str, run: Callable[..., str] = CommandRunner()) -> dict[str, Any]:
    path = _run_path(root, run_id)
    try:
        record = _run_record(path)
    except CloudRunnerError as exc:
        raise CloudRunnerError("unknown run or malformed ledger") from exc
    if record.get("status") == "published":
        return {**record, "duplicate": True}
    if record.get("status") != "submitted" or not record.get("task_id"):
        raise CloudRunnerError("run has no confirmed cloud task id")
    lock = path.with_suffix(".collect.lock")
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise CloudRunnerError("collect is already running or requires reconciliation") from exc
    try:
        os.close(lock_fd)
        task = _find_task(record["task_id"], record["environment"], run)
        if task is None:
            raise CloudRunnerError("cloud task id is missing from environment")
        status = run(["codex", "cloud", "status", record["task_id"]])
        if re.match(r"^\[(FAILED|ERROR|CANCELED|CANCELLED)\]", status):
            record.update(status="cloud-failed", cloud_status=status[:500])
            _atomic(path, record)
            raise CloudRunnerError("cloud task ended without a retrievable patch")
        if not status.startswith("[READY]"):
            return {**record, "pending": True,
                    "environment_binding": task.get("environment_binding", "task.environment_id")}
        branch = record["branch"] if record.get("pr") else f"harness/cloud-{run_id}"
        published_head = _remote_head_optional(branch, run)
        if published_head and published_head != record["base_sha"]:
            if record.get("pr"):
                candidates = [_pr_info(record["pr"], run)]
            else:
                candidates = _pages(run(["gh", "api", f"repos/{REPO}/pulls?state=open&head=handlecusion:{branch}",
                                         "--paginate", "--slurp"]), "PR list")
            marker = READY_SHA.format(sha=published_head)
            run_marker = f"<!-- zeropw-run:{run_id} -->"
            matches = [pr for pr in candidates if isinstance(pr.get("head"), dict) and
                       pr["head"].get("sha") == published_head and
                       READY in (pr.get("body") or "") and marker in (pr.get("body") or "") and
                       run_marker in (pr.get("body") or "")]
            if len(matches) == 1:
                record.update(status="published", commit_sha=published_head,
                              publication_branch=branch, pr=matches[0]["number"])
                _atomic(path, record)
                return {**record, "reconciled": True}
            raise CloudRunnerError("published branch exists without a matching ready PR; manual reconciliation required")
        patch = run(["codex", "cloud", "diff", record["task_id"], "--attempt", "1"])
        current = _remote_head(record["branch"], run)
        if current != record["base_sha"]:
            raise CloudRunnerError("remote branch moved since submit")
        if record.get("pr") and _pr_info(record["pr"], run)["head"]["sha"] != record["base_sha"]:
            raise CloudRunnerError("fix PR head moved before push")
        try:
            commit = _materialize(record, patch, branch, run)
        except ApprovalRequired as exc:
            record.update(status="needs-approval",
                          reason="Cloud patch changes trusted control-plane files; automatic push blocked",
                          approval_paths=exc.paths[:100])
            _atomic(path, record)
            return {**record, "attention_required": True}
        marker = READY + "\n" + READY_SHA.format(sha=commit) + f"\n<!-- zeropw-run:{run_id} -->"
        if record.get("pr"):
            pr = _pr_info(record["pr"], run)
            if pr["head"]["sha"] != commit:
                raise CloudRunnerError("fix PR head does not match pushed commit")
            body = pr.get("body") or ""
            body = re.sub(r"\n?<!-- zeropw:ready-for-review -->|\n?<!-- zeropw-ready-sha:[^>]+ -->|\n?<!-- zeropw-run:[^>]+ -->", "", body)
            run(["gh", "api", "-X", "PATCH", f"repos/{REPO}/pulls/{record['pr']}",
                 "-f", f"body={body.rstrip()}\n\n{marker}"])
            pr_number = record["pr"]
        else:
            response = _json_dict(run(["gh", "api", "-X", "POST", f"repos/{REPO}/pulls", "-f",
                                   f"head={branch}", "-f", "base=main", "-f", f"title=Codex Cloud {run_id}",
                                   "-f", f"body={marker}"]), "PR creation response")
            if not isinstance(response.get("number"), int):
                raise CloudRunnerError("malformed PR creation response: missing number")
            pr_number = response["number"]
        record.update(status="published", commit_sha=commit, publication_branch=branch, pr=pr_number)
        _atomic(path, record)
        return record
    finally:
        if lock.exists():
            lock.unlink()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("submit")
    s.add_argument("--prompt-file", type=Path, required=True)
    s.add_argument("--branch", default="main")
    s.add_argument("--pr", type=int)
    s.add_argument("--review-sha")
    c = sub.add_parser("collect")
    c.add_argument("--run", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = Path.cwd()
    try:
        result = (submit(root, args.prompt_file, args.branch, args.pr, args.review_sha)
                  if args.command == "submit" else collect(root, args.run))
        print(json.dumps(result, sort_keys=True))
        return 0
    except CloudRunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
