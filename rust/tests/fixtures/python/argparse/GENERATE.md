# Python-prototype fixtures: `argparse`

What CPython 3.12's `argparse` printed (exit code, stdout, stderr; COLUMNS=80) for a sample parser shaped like the administrator CLI, and `textwrap.wrap` lines. Stdlib only; recorded because the prototype's CLIs used `argparse` and its user-visible output is a feature.

Used by rust/src/argparse.rs. Everything here is synthetic test material; no real
credential, key or host is involved.

Generated once on 2026-10-03, before the Python prototype was deleted, with
CPython 3.12.14 in the isolated `zeropw-parity` VM, from the repository root
of branch `claude/pc-cvcore` (based on `claude/rust-parity-close` 942a963):

```
rm -rf rust/tests/fixtures/python/argparse
PYTHONPATH=. PYTHONDONTWRITEBYTECODE=1 python3.12 argparse_cases.py rust/tests/fixtures/python/argparse
```

(`vmrun.sh <worktree> cvcore bash -c '...'` ran that command against a copy of
the worktree and streamed the output directory back as a tar archive.)
Re-running produces different random keys, ids and salts; the tests only
depend on what the files record, not on particular random values.

`argparse_cases.py`:

```python
# Generates rust/tests/fixtures/python/argparse/cases.json with CPython 3.12's
# argparse/textwrap (the behaviour the prototype's CLIs had). No zeropw import.
import contextlib, io, json, os, pathlib, sys, textwrap
import argparse, sys, io, contextlib, json
class NoAbbrev(argparse.ArgumentParser):
    # Like admin_cli._Parser: every (sub)parser disables abbreviation.
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
def build(allow):
    cls = argparse.ArgumentParser if allow else NoAbbrev
    p = cls(prog="prog", description="A tool (trusted; JSON output).")
    p.add_argument("--state-dir", required=True, metavar="DIR", help="trusted state directory (0700)")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    put = sub.add_parser("put", help="store a new secret version; value via --value-file or --stdin only", description="store a new secret version; value via --value-file or --stdin only")
    put.add_argument("--id", required=True)
    put.add_argument("--kind", required=True, choices=("api_key", "password"))
    put.add_argument("--version", type=int)
    put.add_argument("--staged", action="store_true", help="store without activating")
    g = put.add_mutually_exclusive_group(required=True)
    g.add_argument("--value-file", metavar="PATH", help="read the secret value from this file (delete it afterwards)")
    g.add_argument("--stdin", action="store_true", help="read the secret value from standard input")
    join = sub.add_parser("join", help="dial the inviter, prove the invite, and join")
    join.add_argument("invite")
    join.add_argument("--project", help="local project name (default: derived from the inviter)")
    return p

CASES = [
            [],
            ["-h"],
            ["--state-dir", "s", "put", "-h"],
            ["--state-dir", "s", "put"],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "nope",
                "--stdin",
            ],
            ["--state-dir", "s", "put", "--id", "x", "--kind", "api_key"],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--value-file",
                "f",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--version",
                " 5_0",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--version",
                "abc",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "-x",
                "--kind",
                "api_key",
                "--stdin",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind=api_key",
                "--stdin",
                "--value",
                "v",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin=1",
            ],
            ["--state-dir", "s", "join"],
            ["--state-dir", "s", "join", "a", "b"],
            ["--state-dir", "s", "join", "--", "-a"],
            ["--state-dir", "s", "join", "-5"],
            ["--state-dir", "s", "join", "x", "-hfoo"],
            ["--state-dir", "s", "bogus"],
            ["put"],
            ["--state-dir"],
            ["--state-dir=s", "join", "a b", "--project", ""],
            ["--state", "s", "join", "a", "--proj", "p"],
            [
                "--state-dir",
                "s",
                "put",
                "--i",
                "x",
                "--k",
                "api_key",
                "--st",
            ],
            [
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--s",
            ],
]
TEXTS = [
            "start team sync on a separate LAN/VPN-facing socket (default: team sync off)",
            "open an incident: lock down the given scope (docs/compromise-response.md §4)",
            "a very-long-hyphenated-compound-word-that-must-break and x--y em -- dash --foo",
            "supercalifragilisticexpialidocious-and-more-words-here ok",
            "30m, 1h, 3600s, 86400 (default: 1h; max 30d)",
]
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
parse = []
for abbrev in (False, True):
    for argv in CASES:
        os.environ["COLUMNS"] = "80"
        o, e = io.StringIO(), io.StringIO()
        code = None
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                ns, extras = build(abbrev).parse_known_args(argv)
                print(json.dumps(sorted((k, v) for k, v in vars(ns).items() if k != "handler")), extras)
            except SystemExit as exc:
                code = exc.code
        parse.append({"argv": argv, "columns": 80, "abbrev": abbrev, "expected": [code, o.getvalue(), e.getvalue()]})
wrap = [{"text": t, "width": w, "lines": textwrap.wrap(t, w)} for w in (11, 22, 54) for t in TEXTS]
(out / "cases.json").write_text(json.dumps({"parse": parse, "wrap": wrap}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
```
