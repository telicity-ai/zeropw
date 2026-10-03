//! Differential tests of `bytes.decode(charset, 'strict' | 'surrogateescape')`
//! for the multibyte CJK codecs, UTF-16/32/7, the escape codecs, punycode
//! and IDNA against CPython 3.12.14 (`crate::oracle::python`): every case
//! is decoded by both, and the decoded code points (lone surrogates
//! included) or the exception class must agree.

use super::{Decoded, Ex, decode_with, lookup_codec, text};

/// The Python side: `cases()` (defined by each test) yields `(charset,
/// bytes)`; each line of output is `charset hex strict escape`, tab
/// separated.
const PRELUDE: &str = r#"
import base64, codecs, random, sys, unicodedata
def res(b, enc, err):
    try:
        s = b.decode(enc, err)
    except UnicodeDecodeError:
        return "D"
    except LookupError:
        return "L"
    except RuntimeError:
        return "R"
    except ValueError:
        return "V"
    except Exception as e:
        return "X:" + type(e).__name__
    return s.encode("utf-32-be", "surrogatepass").hex()
"#;

const POSTLUDE: &str = r#"
out = []
for enc, b in cases():
    out.append("%s\t%s\t%s\t%s" % (enc, b.hex(), res(b, enc, "strict"), res(b, enc, "surrogateescape")))
sys.stdout.write("\n".join(out))
"#;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// This port's `bytes.decode(charset, errors)`, in the oracle's notation.
fn rust_result(charset: &str, bytes: &[u8], escape: bool) -> String {
    // `bytes.decode` returns '' for empty bytes before any codec lookup
    // (`ew_decode` does the same).
    if bytes.is_empty() {
        return String::new();
    }
    let Some(codec) = lookup_codec(&text(charset)) else {
        return "L".into();
    };
    match decode_with(codec, bytes, escape) {
        Ok(Decoded::Ok(decoded)) => decoded.iter().map(|c| format!("{c:08x}")).collect(),
        Ok(Decoded::DecodeError) => "D".into(),
        Err(Ex::InvalidEw) => "V".into(),
        Err(Ex::Builtin("RuntimeError")) => "R".into(),
        Err(other) => format!("X:{other:?}"),
    }
}

/// Runs `cases` (Python defining `cases()`) through CPython and this port;
/// returns the number of cases compared.
fn assert_matches_python(cases: &str) -> usize {
    let script = format!("{PRELUDE}\n{cases}\n{POSTLUDE}");
    let output = crate::oracle::python(&script);
    let mut mismatches = Vec::new();
    let mut count = 0;
    for line in output.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [charset, input, strict, escape] = fields[..] else {
            panic!("bad oracle line {line:?}");
        };
        count += 1;
        let bytes = unhex(input);
        let rust_strict = rust_result(charset, &bytes, false);
        let rust_escape = rust_result(charset, &bytes, true);
        if rust_strict != strict || rust_escape != escape {
            mismatches.push(format!(
                "{charset} {input}: python {strict} / {escape}, rust {rust_strict} / {rust_escape}"
            ));
        }
    }
    assert!(count > 0, "the oracle produced no cases");
    assert!(
        mismatches.is_empty(),
        "{} of {count} cases differ:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    count
}

const CN: &str = "['gb2312', 'gbk', 'gb18030', 'hz']";
const TW_HK: &str = "['big5', 'cp950', 'big5hkscs']";
const KR: &str = "['euc_kr', 'cp949', 'johab']";
const JP: &str = "['cp932', 'euc_jp', 'shift_jis', 'euc_jis_2004', 'euc_jisx0213', 'shift_jis_2004', 'shift_jisx0213']";
const ISO2022: &str = "['iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr']";

/// Every one- and two-byte input, then random short byte strings biased
/// toward lead/trail byte ranges, and valid encodings of random text cut
/// at every position.
fn exhaustive_two_byte(codecs: &str) -> String {
    format!(
        r#"
CODECS = {codecs}
def cases():
    rng = random.Random(20261003)
    for enc in CODECS:
        for a in range(256):
            yield enc, bytes([a])
        for a in range(256):
            for b in range(256):
                yield enc, bytes([a, b])
        def byte():
            r = rng.random()
            if r < 0.5: return rng.randrange(0x80, 0x100)
            if r < 0.65: return rng.randrange(0x30, 0x3a)
            if r < 0.9: return rng.randrange(0x40, 0x7f)
            return rng.randrange(0, 0x30)
        for _ in range(6000):
            yield enc, bytes(byte() for _ in range(rng.randrange(1, 9)))
        pool = []
        for cp in range(0x80, 0x30000):
            try:
                pool.append(chr(cp).encode(enc))
            except (UnicodeEncodeError, ValueError):
                pass
        for _ in range(1500):
            raw = b"".join(rng.choice(pool) if rng.random() < 0.8 else bytes([rng.randrange(0x20, 0x7f)]) for _ in range(rng.randrange(1, 5)))
            for cut in range(len(raw) + 1):
                yield enc, raw[:cut]
            if raw:
                i = rng.randrange(len(raw))
                yield enc, raw[:i] + bytes([rng.randrange(256)]) + raw[i + 1:]
"#
    )
}

#[test]
fn chinese_codecs_match_python() {
    assert_matches_python(&exhaustive_two_byte(CN));
}

#[test]
fn traditional_chinese_codecs_match_python() {
    assert_matches_python(&exhaustive_two_byte(TW_HK));
}

#[test]
fn korean_codecs_match_python() {
    assert_matches_python(&exhaustive_two_byte(KR));
}

#[test]
fn japanese_codecs_match_python() {
    assert_matches_python(&exhaustive_two_byte(JP));
}

#[test]
fn iso2022_codecs_two_byte_inputs_match_python() {
    assert_matches_python(&exhaustive_two_byte(ISO2022));
}

/// Three-byte JIS X 0212 / JIS X 0213 plane 2 sequences (`0x8F` lead),
/// exhaustively.
#[test]
fn euc_jp_three_byte_sequences_match_python() {
    assert_matches_python(
        r#"
def cases():
    for enc in ['euc_jp', 'euc_jis_2004', 'euc_jisx0213']:
        for b in range(256):
            for c in range(256):
                yield enc, bytes([0x8f, b, c])
"#,
    );
}

/// gb18030's four-byte sequences: every BMP sequence, a stride through the
/// supplementary planes, and the boundaries around them.
#[test]
fn gb18030_four_byte_sequences_match_python() {
    assert_matches_python(
        r#"
def four(lseq, c0=0x81):
    c1, r = divmod(lseq, 12600)
    c2, r = divmod(r, 1260)
    c3, c4 = divmod(r, 10)
    return bytes([c0 + c1, 0x30 + c2, 0x81 + c3, 0x30 + c4])
def cases():
    rng = random.Random(18030)
    for lseq in range(0, 4 * 12600):
        yield 'gb18030', four(lseq)
    for lseq in range(0, 126 * 12600, 7):
        yield 'gb18030', four(lseq)
    edges = [0x2f, 0x30, 0x39, 0x3a, 0x7f, 0x80, 0x81, 0x82, 0x84, 0x85, 0x8f, 0x90, 0xe3, 0xe4, 0xfd, 0xfe, 0xff]
    for a in edges:
        for b in edges:
            for c in edges:
                for d in edges:
                    yield 'gb18030', bytes([a, b, c, d])
    for _ in range(20000):
        yield 'gb18030', bytes([rng.randrange(0x80, 0x100), rng.randrange(0x30, 0x3a), rng.randrange(0x80, 0x100), rng.randrange(0x2f, 0x3b)])[:rng.randrange(1, 5)]
"#,
    );
}

/// euc_kr's KS X 1001:1998 Hangul make-up sequences (`A4 D4 A4 x A4 y A4 z`).
#[test]
fn euc_kr_jamo_sequences_match_python() {
    assert_matches_python(
        r#"
def cases():
    rng = random.Random(1001)
    values = [0x00, 0x41, 0xa0, 0xa1, 0xa3, 0xa4, 0xb0, 0xbe, 0xbf, 0xc0, 0xd3, 0xd4, 0xd5, 0xfe, 0xff]
    for x in values:
        for y in values:
            for z in values:
                yield 'euc_kr', bytes([0xa4, 0xd4, 0xa4, x, 0xa4, y, 0xa4, z])
    for x in range(0xa1, 0xbf):
        for y in range(0xbf, 0xd4):
            yield 'euc_kr', bytes([0xa4, 0xd4, 0xa4, x, 0xa4, y, 0xa4, rng.choice([0xd4] + list(range(0xa1, 0xbf)))])
    for _ in range(3000):
        raw = bytearray([0xa4, 0xd4, 0xa4, rng.randrange(0xa1, 0xbf), 0xa4, rng.randrange(0xbf, 0xd4), 0xa4, 0xd4])
        if rng.random() < 0.5:
            raw[rng.choice([2, 4, 6])] = rng.randrange(256)
        yield 'euc_kr', bytes(raw[:rng.randrange(1, 9)]) + bytes([rng.randrange(256)]) * rng.randrange(0, 2)
"#,
    );
}

/// The stateful codecs (ISO-2022 designations, shifts, single shifts and
/// "ESC throughout" mode; hz shifts) over random token sequences.
#[test]
fn stateful_codecs_match_python() {
    assert_matches_python(&format!(
        r#"
CODECS = {ISO2022} + ['hz']
TOKENS = [b"\x1b(B", b"\x1b(J", b"\x1b(I", b"\x1b(A", b"\x1b(F", b"\x1b$@", b"\x1b$B", b"\x1b$A",
          b"\x1b$(C", b"\x1b$)C", b"\x1b$(D", b"\x1b$(O", b"\x1b$(P", b"\x1b$(Q", b"\x1b$C",
          b"\x1b.A", b"\x1b.F", b"\x1b.B", b"\x1b.J", b"\x1bN", b"\x1b&@\x1b$B", b"\x1b&@", b"\x1b&@\x1b$A",
          b"\x1b(", b"\x1b$", b"\x1b$(", b"\x1b", b"\x1bX", b"\x1b(Z", b"\x1b$)A", b"\x1b((((((((((((((((B",
          b"\x0e", b"\x0f", b"\n", b"~{{", b"~}}", b"~~", b"~\n", b"~", b"~x",
          b"!", b"\"", b"$", b"0", b"A", b"[", b"\\", b"~", b"\x7f", b"\x20", b"\x01",
          b"!!", b"0!", b"$\"", b"%t", b"&!", b"?~", b"P!", b"t'", b"~~", b".!", b"O~", b"}}~", b"!@", b"\"2",
          b"\x80", b"\xa1", b"\xff", b"\xa1\xa1", b"\xb0\xa1"]
def cases():
    rng = random.Random(2022)
    for enc in CODECS:
        for a in TOKENS:
            for b in TOKENS:
                yield enc, a + b
        for _ in range(12000):
            yield enc, b"".join(rng.choice(TOKENS) for _ in range(rng.randrange(1, 9)))
        pool = []
        for cp in list(range(0x20, 0x80)) + list(range(0xa0, 0x30000, 3)):
            try:
                pool.append(chr(cp).encode(enc))
            except (UnicodeEncodeError, ValueError):
                pass
        for _ in range(1500):
            raw = rng.choice(pool) + rng.choice(pool) + rng.choice(pool)
            for cut in range(len(raw) + 1):
                yield enc, raw[:cut]
"#
    ));
}

/// UTF-16 and UTF-32 with and without a BOM: every input up to two bytes,
/// and random sequences of code units around the surrogate, BOM and range
/// boundaries with stray trailing bytes.
#[test]
fn utf16_and_utf32_match_python() {
    assert_matches_python(
        r#"
def cases():
    rng = random.Random(1632)
    for enc in ['utf-16', 'utf-16-le', 'utf-16-be', 'utf_16', 'UTF16', 'utf-16le', 'u16']:
        for a in range(256):
            yield enc, bytes([a])
        for a in range(256):
            for b in range(256):
                yield enc, bytes([a, b])
    units16 = [0x0041, 0x00e9, 0x0080, 0x00ff, 0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdc80, 0xdfff, 0xe000, 0xfeff, 0xfffe, 0xffff, 0x4e00, 0x8000, 0x0000, 0x2000]
    for enc, order in [('utf-16', '<'), ('utf-16-le', '<'), ('utf-16-be', '>')]:
        for _ in range(12000):
            raw = b"".join(rng.choice(units16).to_bytes(2, 'little' if rng.random() < 0.5 else 'big') for _ in range(rng.randrange(0, 6)))
            yield enc, raw + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 2)))
    units32 = [0x41, 0xe9, 0x80, 0xdc80, 0xd800, 0xdfff, 0xfeff, 0xfffe0000, 0x10ffff, 0x110000, 0x80000000, 0xffffffff, 0x1f600, 0x0, 0x8080, 0x80808080]
    for enc in ['utf-32', 'utf-32-le', 'utf-32-be', 'utf_32', 'U32', 'utf32']:
        for a in range(256):
            yield enc, bytes([a])
        for _ in range(12000):
            raw = b"".join(rng.choice(units32).to_bytes(4, 'little' if rng.random() < 0.5 else 'big') for _ in range(rng.randrange(0, 5)))
            yield enc, raw + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 4)))
"#,
    );
}

#[test]
fn utf7_matches_python() {
    assert_matches_python(
        r#"
def cases():
    rng = random.Random(7)
    alphabet = [b"+", b"-", b"A", b"B", b"Z", b"a", b"z", b"0", b"9", b"/", b" ", b"!", b"~", b"\\", b"\x80", b"\xff", b"\xc3", b"\n",
                b"+AAA", b"+AGE", b"+2D3cAA", b"+2D3cAA-", b"+2D0", b"+3AA", b"+AGEAYQ", b"+AGEAYQ-", b"+ZeVnLIqe-", b"+-", b"+2D3cAN", b"+AH"]
    for a in range(256):
        yield 'utf-7', bytes([a])
    for a in range(256):
        for b in range(256):
            yield 'utf-7', bytes([a, b])
    for enc in ['utf-7', 'utf_7', 'U7', 'unicode-1-1-utf-7']:
        for _ in range(15000):
            yield enc, b"".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 8)))
    for _ in range(3000):
        s = "".join(chr(rng.choice([rng.randrange(0x20, 0x7f), rng.randrange(0x80, 0x800), rng.randrange(0xd800, 0xe000), rng.randrange(0x10000, 0x110000)])) for _ in range(rng.randrange(1, 5)))
        raw = s.encode('utf-16-be', 'surrogatepass')
        b64 = base64.b64encode(raw).rstrip(b"=")
        for cut in range(len(b64) + 1):
            yield 'utf-7', b"+" + b64[:cut] + rng.choice([b"", b"-", b" ", b"\x80", b"!"])
"#,
    );
}

#[test]
fn unicode_escape_codecs_match_python() {
    assert_matches_python(
        r#"
def cases():
    rng = random.Random(92)
    frags = [b"\\", b"x", b"u", b"U", b"N", b"{", b"}", b"0", b"7", b"8", b"a", b"F", b"g", b"4", b"1", b"\x80", b"\xff", b"\n", b"'", b'"',
             b"b", b"f", b"t", b"n", b"r", b"v", b"q", b"N{LATIN SMALL LETTER A}", b"N{latin small letter a}", b"N{HANGUL SYLLABLE GA}",
             b"N{CJK UNIFIED IDEOGRAPH-4E00}", b"N{BEL}", b"N{}", b"N{NOPE}", b"U0010FFFF", b"U00110000", b"uD800", b"x4", b"777", b"400"]
    for enc in ['unicode_escape', 'raw_unicode_escape', 'unicode-escape', 'raw-unicode-escape']:
        for a in range(256):
            yield enc, bytes([a])
            yield enc, b"\\" + bytes([a])
        for _ in range(15000):
            yield enc, b"".join(rng.choice(frags) for _ in range(rng.randrange(1, 8)))
"#,
    );
}

/// `\N{...}` for every name `unicodedata` reports, every Hangul syllable,
/// the CJK ideograph ranges' edges, lower-case and malformed variants, and
/// every name alias this port knows.
#[test]
fn unicode_escape_names_match_python() {
    let aliases: Vec<String> = super::unicode_tables::NAME_ALIASES
        .iter()
        .map(|(name, _)| format!("{name:?}"))
        .collect();
    assert_matches_python(&format!(
        r#"
ALIASES = [{}]
def cases():
    rng = random.Random(15)
    names = []
    for cp in range(0x110000):
        n = unicodedata.name(chr(cp), None)
        if n is not None:
            names.append(n)
    for n in names:
        yield 'unicode_escape', ("\\N{{" + n + "}}").encode()
    for n in rng.sample(names, 3000) + ALIASES:
        yield 'unicode_escape', ("\\N{{" + n + "}}").encode()
        yield 'unicode_escape', ("\\N{{" + n.lower() + "}}").encode()
        yield 'unicode_escape', ("\\N{{" + n + " }}").encode()
        yield 'unicode_escape', ("\\N{{" + n[:-1] + "}}").encode()
    for h in ["HANGUL SYLLABLE ", "HANGUL SYLLABLE", "HANGUL SYLLABLE GAX", "HANGUL SYLLABLE KKK", "HANGUL SYLLABLE A", "HANGUL SYLLABLE YI", "HANGUL SYLLABLE GGWAELH"]:
        yield 'unicode_escape', ("\\N{{" + h + "}}").encode()
    for cjk in ["3400", "4DBF", "4DC0", "9FFF", "A000", "20000", "2A6DF", "2A6E0", "323AF", "323B0", "4e00", "04E00", "4E0", "4E00 ", "G000", "0000", "FFFFF"]:
        yield 'unicode_escape', ("\\N{{CJK UNIFIED IDEOGRAPH-" + cjk + "}}").encode()
"#,
        aliases.join(", ")
    ));
}

#[test]
fn punycode_and_idna_match_python() {
    assert_matches_python(
        r#"
def cases():
    rng = random.Random(3492)
    words = []
    for _ in range(2000):
        s = "".join(chr(rng.choice([rng.randrange(0x61, 0x7b), rng.randrange(0x41, 0x5b), rng.randrange(0x30, 0x3a), 0x2d, rng.randrange(0xc0, 0x250), rng.randrange(0x370, 0x3ff), rng.randrange(0x400, 0x4ff), rng.randrange(0x5d0, 0x5ea), rng.randrange(0x620, 0x64a), rng.randrange(0x3041, 0x3097), rng.randrange(0x4e00, 0x9fa5), rng.randrange(0xac00, 0xd7a3), rng.randrange(0xff01, 0xff5e), rng.randrange(0x300, 0x370), 0xdf, 0x130, 0x3a3, 0xad, 0x200d, 0xfb01, 0x2163, rng.randrange(0x10000, 0x110000)])) for _ in range(rng.randrange(1, 7)))
        words.append(s)
    for s in words:
        enc = s.encode('punycode')
        yield 'punycode', enc
        yield 'punycode', enc.upper()
        for cut in range(len(enc)):
            yield 'punycode', enc[:cut]
        if enc:
            i = rng.randrange(len(enc))
            yield 'punycode', enc[:i] + bytes([rng.choice(b"az09-AZ_\x80")]) + enc[i + 1:]
        yield 'idna', b"xn--" + enc
        yield 'idna', b"XN--" + enc
        yield 'idna', b"xn--" + enc.upper() + b".example."
        yield 'idna', b"a." + b"xn--" + enc + b"..b"
        try:
            yield 'idna', s.encode('idna')
            yield 'idna', s.encode('idna').upper()
        except UnicodeError:
            pass
    alphabet = [b"xn--", b"-", b"a", b"z", b"A", b"0", b"9", b".", b"\x80", b"\xff", b"__", b"zz", b"99", b"ba", b"xn"]
    for enc in ['punycode', 'idna']:
        for _ in range(8000):
            yield enc, b"".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 8)))
    yield 'idna', b"xn--" + b"a" * 1100
    yield 'idna', b"a" * 70
    yield 'idna', b"."
    yield 'idna', b".."
    yield 'idna', b"xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    yield 'punycode', b"99999999999999999999999999999999999999999999999999999999999999999999"
"#,
    );
}

/// Every alias and normalized spelling CPython resolves to one of these
/// codecs decodes the same.
#[test]
fn codec_aliases_match_python() {
    assert_matches_python(
        r#"
import encodings.aliases
TARGETS = {'big5', 'big5hkscs', 'cp932', 'cp949', 'cp950', 'euc_jis_2004', 'euc_jisx0213', 'euc_jp', 'euc_kr',
           'gb18030', 'gb2312', 'gbk', 'hz', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004',
           'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr', 'johab', 'shift_jis', 'shift_jis_2004',
           'shift_jisx0213', 'utf_16', 'utf_16_be', 'utf_16_le', 'utf_32', 'utf_32_be', 'utf_32_le', 'utf_7',
           'idna', 'punycode', 'unicode_escape', 'raw_unicode_escape'}
def cases():
    names = sorted(TARGETS) + sorted(k for k, v in encodings.aliases.aliases.items() if v in TARGETS)
    samples = [b"abc", b"\xa4\xa1\xb0\xa1", b"\x1b$B$\"\x1b(B", b"\xff\xfeA\x00", b"\x00\x00\xfe\xff", b"+AGE-", b"\\u00e9", b"xn--mnchen-3ya", b"~{<:~}"]
    for n in names:
        for spelling in {n, n.upper(), n.replace('_', '-'), n.replace('_', ' '), '  ' + n + '  ', n.replace('_', '.')}:
            if '\0' in spelling:
                continue
            for b in samples:
                yield spelling, b
"#,
    );
}

/// `unicodedata.ucd_3_2_0.normalize("NFKC", ...)` for every code point and
/// for random combining sequences.
#[test]
fn nfkc_3_2_matches_python() {
    let script = r#"
import random, sys, unicodedata
u = unicodedata.ucd_3_2_0
out = []
for cp in range(0x110000):
    c = chr(cp)
    n = u.normalize("NFKC", c)
    if n != c:
        out.append("%x %s" % (cp, n.encode("utf-32-be", "surrogatepass").hex()))
rng = random.Random(15)
marks = [cp for cp in range(0x300, 0x370)] + [0x93c, 0x94d, 0x9bc, 0x9be, 0x9d7, 0xb3e, 0xb56, 0xb57, 0xbbe, 0xbd7, 0xcc2, 0xcd5, 0xcd6, 0xd3e, 0xd57, 0xdca, 0xdcf, 0xddf, 0x102e, 0x1b35, 0x3099, 0x309a, 0x1161, 0x1175, 0x11a8, 0x11c2, 0x05b0, 0x05bc, 0x0f71, 0x0f72, 0x0f80, 0x1d165, 0x1d16e]
bases = [0x41, 0x61, 0x45, 0x65, 0x4f, 0x6f, 0x55, 0x3b1, 0x3c9, 0x415, 0x928, 0x9c7, 0xb47, 0xb92, 0xbc6, 0xcc6, 0xd46, 0xdd9, 0x1025, 0x1b05, 0x304b, 0x30cf, 0x1100, 0x1112, 0xac00, 0x5d0, 0xfb2a, 0x1d157, 0x212b, 0xfb01, 0x1e9b, 0x2000, 0xffc2]
for _ in range(20000):
    s = "".join(chr(rng.choice(marks) if rng.random() < 0.6 else rng.choice(bases)) for _ in range(rng.randrange(1, 7)))
    out.append("s%s %s" % (s.encode("utf-32-be").hex(), u.normalize("NFKC", s).encode("utf-32-be", "surrogatepass").hex()))
sys.stdout.write("\n".join(out))
"#;
    let output = crate::oracle::python(script);
    let mut changed = std::collections::BTreeMap::new();
    let mut mismatches = Vec::new();
    let utf32 = |hex: &str| -> Vec<u32> {
        unhex(hex)
            .chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    };
    for line in output.lines() {
        let (input, expected) = line.split_once(' ').unwrap();
        let expected = utf32(expected);
        if let Some(sequence) = input.strip_prefix('s') {
            let sequence = utf32(sequence);
            let actual = super::unicodec::nfkc_3_2_for_test(&sequence);
            if actual != expected {
                mismatches.push(format!(
                    "{sequence:x?}: python {expected:x?}, rust {actual:x?}"
                ));
            }
        } else {
            changed.insert(u32::from_str_radix(input, 16).unwrap(), expected);
        }
    }
    for cp in 0..0x110000u32 {
        let actual = super::unicodec::nfkc_3_2_for_test(&[cp]);
        let expected = changed.get(&cp).cloned().unwrap_or_else(|| vec![cp]);
        if actual != expected {
            mismatches.push(format!("{cp:x}: python {expected:x?}, rust {actual:x?}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} differ:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(40)].join("\n")
    );
}

/// `encodings.idna.nameprep` for every code point alone and for random
/// labels.
#[test]
fn nameprep_matches_python() {
    let script = r#"
import random, sys
from encodings.idna import nameprep
def res(s):
    try:
        return nameprep(s).encode("utf-32-be", "surrogatepass").hex()
    except UnicodeError:
        return "E"
out = []
for cp in range(0x110000):
    c = chr(cp)
    r = res(c)
    if r != c.encode("utf-32-be", "surrogatepass").hex():
        out.append("%x %s" % (cp, r))
rng = random.Random(3491)
pool = [0x41, 0x61, 0xdf, 0x130, 0x3a3, 0xad, 0x200d, 0xfb01, 0x2163, 0x5d0, 0x5d1, 0x627, 0x661, 0x30, 0x20, 0x3000, 0xe000, 0xfdd0, 0x300, 0x301, 0x1e9b, 0x323, 0x2f868, 0x2f9bf, 0x1100, 0x1161, 0x11a8, 0xff21, 0x2126, 0x340, 0x0345, 0x3b9]
for _ in range(20000):
    s = "".join(chr(rng.choice(pool)) for _ in range(rng.randrange(1, 6)))
    out.append("s%s %s" % (s.encode("utf-32-be").hex(), res(s)))
sys.stdout.write("\n".join(out))
"#;
    let output = crate::oracle::python(script);
    let utf32 = |hex: &str| -> Vec<u32> {
        unhex(hex)
            .chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    };
    let render = |r: Option<Vec<u32>>| match r {
        Some(v) => hex(&v.iter().flat_map(|c| c.to_be_bytes()).collect::<Vec<u8>>()),
        None => "E".into(),
    };
    let mut changed = std::collections::BTreeMap::new();
    let mut mismatches = Vec::new();
    for line in output.lines() {
        let (input, expected) = line.split_once(' ').unwrap();
        if let Some(sequence) = input.strip_prefix('s') {
            let sequence = utf32(sequence);
            let actual = render(super::unicodec::nameprep_for_test(&sequence));
            if actual != expected {
                mismatches.push(format!("{sequence:x?}: python {expected}, rust {actual}"));
            }
        } else {
            changed.insert(u32::from_str_radix(input, 16).unwrap(), expected.to_owned());
        }
    }
    for cp in 0..0x110000u32 {
        let actual = render(super::unicodec::nameprep_for_test(&[cp]));
        let expected = changed
            .get(&cp)
            .cloned()
            .unwrap_or_else(|| format!("{cp:08x}"));
        if actual != expected {
            mismatches.push(format!("{cp:x}: python {expected}, rust {actual}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} differ:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(40)].join("\n")
    );
}
