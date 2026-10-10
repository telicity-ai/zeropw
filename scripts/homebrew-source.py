#!/usr/bin/env python3
"""Pin a local verification formula to one source revision."""
import argparse
import pathlib
import re


def pin(source: str, root: str, commit: str) -> str:
    head = 'head "https://github.com/telicity-ai/zeropw.git", branch: "main"'
    if source.count(head) != 1:
        raise ValueError('expected exactly one main-branch head declaration')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('expected a full commit SHA')
    literal = "'" + root.replace('\\', '\\\\').replace("'", "\\'") + "'"
    return source.replace(head, f"head {literal}, using: :git, revision: '{commit}'")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('tap', type=pathlib.Path)
    parser.add_argument('commit')
    args = parser.parse_args()
    output = pin((args.root / 'Formula/zeropw.rb').read_text(), str(args.root), args.commit)
    (args.tap / 'Formula/zeropw.rb').write_text(output)
