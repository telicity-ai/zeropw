#!/usr/bin/env python3.12
"""Generate `UNICODE_DECIMAL_DIGIT_BLOCKS` for `rust/src/team/commit.rs`.

CPython 3.12's `int(str)` accepts any Unicode code point that has a decimal
digit value (`unicodedata.decimal(ch)` does not raise `ValueError`) as a
digit, with that value. Every such code point turns out to belong to a
contiguous block of exactly ten code points holding the digits `0`..`9` in
order (this script *verifies* that invariant against `python3.12` rather than
assuming it), so a block's start alone is enough to recover any digit's
value (`codepoint - start`).

This replaces a previously hand-maintained table that silently fell out of
date (equivalence-review finding H-R2-2: it was missing the Dives Akuru
(`0x11950`) and Kawi (`0x11F50`) blocks, both real Unicode 15.0 `Nd` blocks
that CPython 3.12's `int()` accepts). Run with
`python3.12 rust/tools/gen_digit_table.py` from the repo root and paste the
printed `const` block into `commit.rs` (the table is committed, not
generated at build time). Re-run and repaste if this crate ever moves to a
newer `python3.12`/UCD version.

The ASCII block (`0x30`..`0x39`) is deliberately excluded from the printed
table: `commit.rs`'s `unicode_digit_value` already special-cases
`char::is_ascii_digit()` before consulting this table.
"""

import sys
import unicodedata

SURROGATE_LO = 0xD800
SURROGATE_HI = 0xDFFF
MAX_CODEPOINT = 0x10FFFF
ASCII_ZERO = 0x30


def decimal_digits():
    """Yield (codepoint, digit_value) for every code point with a decimal
    digit value, in ascending order."""
    for cp in range(0, MAX_CODEPOINT + 1):
        if SURROGATE_LO <= cp <= SURROGATE_HI:
            continue
        try:
            value = unicodedata.decimal(chr(cp))
        except ValueError:
            continue
        yield cp, value


def block_starts():
    """Group the codepoints from `decimal_digits()` into blocks of ten and
    return each block's start codepoint, verifying along the way that every
    block really is ten consecutive code points valued `0..=9` in order (the
    invariant `unicode_digit_value` in `commit.rs` relies on)."""
    digits = list(decimal_digits())
    assert len(digits) % 10 == 0, f"digit count {len(digits)} is not a multiple of 10"
    starts = []
    for i in range(0, len(digits), 10):
        block = digits[i : i + 10]
        start_cp = block[0][0]
        for offset, (cp, value) in enumerate(block):
            assert cp == start_cp + offset, f"block at 0x{start_cp:X} is not contiguous"
            assert value == offset, f"block at 0x{start_cp:X} has out-of-order digit values"
        starts.append(start_cp)
    return starts


def format_table(name, starts):
    lines = [f"const {name}: &[u32] = &["]
    per_line = 6
    for i in range(0, len(starts), per_line):
        chunk = starts[i : i + per_line]
        lines.append("    " + " ".join(f"0x{cp:X}," for cp in chunk))
    lines.append("];")
    return "\n".join(lines)


def main():
    starts = block_starts()
    non_ascii = [cp for cp in starts if cp != ASCII_ZERO]

    print(f"# unicodedata.unidata_version = {unicodedata.unidata_version!r}", file=sys.stderr)
    print(f"# python version = {sys.version!r}", file=sys.stderr)
    print(f"# total Nd blocks (incl. ASCII): {len(starts)}", file=sys.stderr)
    print(f"# non-ASCII Nd blocks: {len(non_ascii)}", file=sys.stderr)

    print(format_table("UNICODE_DECIMAL_DIGIT_BLOCKS", non_ascii))


if __name__ == "__main__":
    main()
