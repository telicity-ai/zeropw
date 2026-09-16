#!/usr/bin/env python3.12
"""Generate the static Unicode range tables used by `rust/src/pystr.rs`.

Brute-forces CPython 3.12's `str.isprintable()` and `str.isspace()` over
every Unicode scalar value (`0..=0x10FFFF`, skipping the UTF-16 surrogate
range `0xD800..=0xDFFF`, which Rust's `char` cannot represent), then
compresses each boolean predicate into a sorted list of disjoint inclusive
codepoint ranges. Run with `python3.12 rust/tools/gen_pystr_tables.py` from
the repo root and paste the two `const` blocks it prints into `pystr.rs`
(the tables are committed, not generated at build time).

Also prints `unicodedata.unidata_version` so `pystr.rs`'s module doc can
record which Unicode Character Database version the table was generated
against (CPython 3.12 bundles a fixed UCD version regardless of the host
OS's own Unicode data).
"""

import sys
import unicodedata

SURROGATE_LO = 0xD800
SURROGATE_HI = 0xDFFF
MAX_CODEPOINT = 0x10FFFF


def codepoints():
    for cp in range(0, MAX_CODEPOINT + 1):
        if SURROGATE_LO <= cp <= SURROGATE_HI:
            continue
        yield cp


def ranges_where(predicate):
    """Compress `predicate(cp)` into a sorted list of (start, end) inclusive
    ranges, skipping surrogates the same way `codepoints()` does (so a range
    spanning the surrogate gap is split in two, which is correct: those
    codepoints are simply absent from the domain)."""
    out = []
    start = None
    prev = None
    for cp in codepoints():
        val = predicate(cp)
        if val:
            if start is None:
                start = cp
            elif prev is not None and cp != prev + 1:
                out.append((start, prev))
                start = cp
            prev = cp
        else:
            if start is not None:
                out.append((start, prev))
                start = None
    if start is not None:
        out.append((start, prev))
    return out


def format_ranges(name, ranges):
    lines = [f"pub(crate) static {name}: &[(u32, u32)] = &["]
    for start, end in ranges:
        lines.append(f"    (0x{start:X}, 0x{end:X}),")
    lines.append("];")
    return "\n".join(lines)


def main():
    non_printable = ranges_where(lambda cp: not chr(cp).isprintable())
    space = ranges_where(lambda cp: chr(cp).isspace())

    print(f"# unicodedata.unidata_version = {unicodedata.unidata_version!r}", file=sys.stderr)
    print(f"# python version = {sys.version!r}", file=sys.stderr)
    print(f"# non_printable: {len(non_printable)} ranges", file=sys.stderr)
    print(f"# space: {len(space)} ranges", file=sys.stderr)

    print(format_ranges("NON_PRINTABLE_RANGES", non_printable))
    print()
    print(format_ranges("SPACE_RANGES", space))


if __name__ == "__main__":
    main()
