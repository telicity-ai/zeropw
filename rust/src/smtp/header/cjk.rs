//! CPython 3.12.14's `_multibytecodec` decoders (`Modules/cjkcodecs`), as
//! `bytes.decode(charset[, errors])` runs them: `MultibyteCodec_Decode`
//! (`multibytecodec.c`) driving each codec's `DECODER` function from
//! `_codecs_cn.c`, `_codecs_hk.c`, `_codecs_iso2022.c`, `_codecs_jp.c`,
//! `_codecs_kr.c` and `_codecs_tw.c`, with the decode maps of
//! `mappings_*.h` (`cjk_tables.rs`).
//!
//! Each decoder is ported statement by statement, including where it stops
//! (`return 1`, `MBERR_TOOFEW`, ...), because the error handler's result
//! depends on the exact error range: `multibytecodec_decerror` reports
//! `[position, position + esize)` and `surrogateescape` escapes only the
//! leading non-ASCII bytes of that range, so decoding resumes inside it.

use super::cjk_tables as t;
use super::{DecodeFail, Errors, Text, decode_error};
use std::sync::OnceLock;

/// `UNIINV`: an unmapped decode-map cell.
const UNIINV: u16 = 0xFFFE;
/// `EMPBASE` (`_codecs_jp.c`).
const EMPBASE: u32 = 0x20000;

/// A `struct dbcs_index` decode map (see `cjk_tables.rs` for the encoding).
pub(super) struct DecodeMap {
    pub(super) index: &'static [(u16, u8, u8); 256],
    pub(super) data: &'static str,
    pub(super) cells: OnceLock<Vec<u16>>,
}

impl DecodeMap {
    fn cells(&self) -> &[u16] {
        self.cells.get_or_init(|| {
            self.data
                .chars()
                .map(|c| match u32::from(c) {
                    0x3F => UNIINV,
                    v if v >= 0xF0000 => u16::try_from(v - 0xF0000).unwrap_or(UNIINV),
                    v => u16::try_from(v).unwrap_or(UNIINV),
                })
                .collect()
        })
    }

    /// `TRYMAP_DEC(map, assi, c1, c2)`.
    fn get(&self, c1: u8, c2: u8) -> Option<u32> {
        let (offset, bottom, top) = self.index[usize::from(c1)];
        if c2 < bottom || c2 > top {
            return None;
        }
        let cell = *self
            .cells()
            .get(usize::from(offset) + usize::from(c2 - bottom))?;
        (cell != UNIINV).then_some(u32::from(cell))
    }
}

/// A `struct widedbcs_index` decode map (`Py_UCS4` cells).
pub(super) struct WideDecodeMap {
    pub(super) index: &'static [(u16, u8, u8); 256],
    pub(super) cells: &'static [u32],
}

impl WideDecodeMap {
    /// `TRYMAP_DEC(map, assi, c1, c2)`.
    fn get(&self, c1: u8, c2: u8) -> Option<u32> {
        let (offset, bottom, top) = self.index[usize::from(c1)];
        if c2 < bottom || c2 > top {
            return None;
        }
        let cell = *self
            .cells
            .get(usize::from(offset) + usize::from(c2 - bottom))?;
        (cell != u32::from(UNIINV)).then_some(cell)
    }
}

/// A `_multibytecodec` codec, by its `encodings` module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cjk {
    Big5,
    Big5hkscs,
    Cp932,
    Cp949,
    Cp950,
    EucJis2004,
    EucJisx0213,
    EucJp,
    EucKr,
    Gb18030,
    Gb2312,
    Gbk,
    Hz,
    Iso2022Jp,
    Iso2022Jp1,
    Iso2022Jp2,
    Iso2022Jp2004,
    Iso2022Jp3,
    Iso2022JpExt,
    Iso2022Kr,
    Johab,
    ShiftJis,
    ShiftJis2004,
    ShiftJisx0213,
}

/// What a `DECODER` function returns.
enum Stop {
    /// `0`: the input is exhausted.
    Done,
    /// `e > 0`: an illegal sequence of `e` bytes.
    Illegal(usize),
    /// `MBERR_TOOFEW`: an incomplete sequence (the rest of the input).
    TooFew,
    /// `MBERR_INTERNAL`: `RuntimeError("internal codec error")`.
    Internal,
}

/// `MultibyteCodec_State.c`: the hz shift state, or the ISO-2022 G0-G2
/// designations and flags.
#[derive(Default)]
struct State {
    g: [u8; 3],
    flags: u8,
}

/// The input and the decoder's read position (`*inbuf`).
struct In<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl In<'_> {
    fn left(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// `(*inbuf)[k]`, which the decoders read only after `REQUIRE_INBUF`
    /// (hz reads `INBYTE2` before it, but does not use it).
    fn at(&self, k: usize) -> u8 {
        self.bytes.get(self.pos + k).copied().unwrap_or(0)
    }
}

/// `MultibyteCodec.decode(input, errors)` (`_multibytecodec_MultibyteCodec_decode_impl`).
pub(super) fn decode(codec: Cjk, bytes: &[u8], errors: Errors) -> Result<Text, DecodeFail> {
    let mut out = Text::with_capacity(bytes.len());
    let mut state = State::default();
    if codec == Cjk::Hz {
        // `DECODER_INIT(hz)`.
        state.g[0] = 0;
    } else if iso2022_config(codec).is_some() {
        // `DECODER_INIT(iso2022)`.
        state.flags = 0;
        state.g = [CHARSET_ASCII; 3];
    }
    let mut input = In { bytes, pos: 0 };
    while input.pos < bytes.len() {
        let stop = run(codec, &mut state, &mut input, &mut out);
        // `multibytecodec_decerror`.
        let esize = match stop {
            Stop::Done => break,
            Stop::Illegal(e) => e,
            Stop::TooFew => input.left(),
            Stop::Internal => return Err(DecodeFail::Runtime),
        };
        let start = input.pos;
        input.pos = decode_error(errors, bytes, start, start + esize, &mut out)?;
    }
    Ok(out)
}

fn run(codec: Cjk, state: &mut State, input: &mut In, out: &mut Text) -> Stop {
    match codec {
        Cjk::Gb2312 => gb2312(input, out),
        Cjk::Gbk => gbk(input, out),
        Cjk::Gb18030 => gb18030(input, out),
        Cjk::Hz => hz(state, input, out),
        Cjk::Big5 => big5(input, out),
        Cjk::Cp950 => cp950(input, out),
        Cjk::Big5hkscs => big5hkscs(input, out),
        Cjk::EucKr => euc_kr(input, out),
        Cjk::Cp949 => cp949(input, out),
        Cjk::Johab => johab(input, out),
        Cjk::Cp932 => cp932(input, out),
        Cjk::EucJp => euc_jp(input, out),
        Cjk::ShiftJis => shift_jis(input, out),
        Cjk::EucJis2004 => euc_jis_2004(false, input, out),
        Cjk::EucJisx0213 => euc_jis_2004(true, input, out),
        Cjk::ShiftJis2004 => shift_jis_2004(false, input, out),
        Cjk::ShiftJisx0213 => shift_jis_2004(true, input, out),
        Cjk::Iso2022Jp
        | Cjk::Iso2022Jp1
        | Cjk::Iso2022Jp2
        | Cjk::Iso2022Jp2004
        | Cjk::Iso2022Jp3
        | Cjk::Iso2022JpExt
        | Cjk::Iso2022Kr => match iso2022_config(codec) {
            Some(config) => iso2022(config, state, input, out),
            None => Stop::Internal,
        },
    }
}

// ------------------------------------------------------------ _codecs_cn.c

/// `GBK_DECODE(dc1, dc2, writer)`.
fn gbk_decode(c: u8, c2: u8) -> Option<u32> {
    if c == 0xa1 && c2 == 0xaa {
        Some(0x2014)
    } else if c == 0xa8 && c2 == 0x44 {
        Some(0x2015)
    } else if c == 0xa1 && c2 == 0xa4 {
        Some(0x00b7)
    } else {
        t::GB2312
            .get(c ^ 0x80, c2 ^ 0x80)
            .or_else(|| t::GBKEXT.get(c, c2))
    }
}

fn gb2312(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        match t::GB2312.get(c ^ 0x80, input.at(1) ^ 0x80) {
            Some(decoded) => {
                out.push(decoded);
                input.pos += 2;
            }
            None => return Stop::Illegal(1),
        }
    }
    Stop::Done
}

fn gbk(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        match gbk_decode(c, input.at(1)) {
            Some(decoded) => out.push(decoded),
            None => return Stop::Illegal(1),
        }
        input.pos += 2;
    }
    Stop::Done
}

fn gb18030(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        if (0x30..=0x39).contains(&c2) {
            // 4 bytes sequence.
            if input.left() < 4 {
                return Stop::TooFew;
            }
            let (c3, c4) = (input.at(2), input.at(3));
            if !(0x81..=0xFE).contains(&c)
                || !(0x81..=0xFE).contains(&c3)
                || !(0x30..=0x39).contains(&c4)
            {
                return Stop::Illegal(1);
            }
            let (c, c2, c3, c4) = (
                u32::from(c - 0x81),
                u32::from(c2 - 0x30),
                u32::from(c3 - 0x81),
                u32::from(c4 - 0x30),
            );
            if c < 4 {
                // U+0080 - U+FFFF.
                let lseq = (c * 10 + c2) * 1260 + c3 * 10 + c4;
                if lseq < 39420 {
                    let ranges = t::GB18030_TO_UNIBMP_RANGES;
                    let mut utr = 0;
                    while ranges.get(utr + 1).is_some_and(|next| lseq >= next.2) {
                        utr += 1;
                    }
                    let Some(&(first, _, base)) = ranges.get(utr) else {
                        return Stop::Internal;
                    };
                    out.push(first.wrapping_sub(base).wrapping_add(lseq));
                    input.pos += 4;
                    continue;
                }
            } else if c >= 15 {
                // U+10000 - U+10FFFF.
                let lseq = 0x10000 + ((c - 15) * 10 + c2) * 1260 + c3 * 10 + c4;
                if lseq <= 0x10FFFF {
                    out.push(lseq);
                    input.pos += 4;
                    continue;
                }
            }
            return Stop::Illegal(1);
        }
        match gbk_decode(c, c2).or_else(|| t::GB18030EXT.get(c, c2)) {
            Some(decoded) => out.push(decoded),
            None => return Stop::Illegal(1),
        }
        input.pos += 2;
    }
    Stop::Done
}

fn hz(state: &mut State, input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c == b'~' {
            let c2 = input.at(1);
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let gb = state.g[0];
            if c2 == b'~' && gb == 0 {
                out.push(u32::from(b'~'));
            } else if c2 == b'{' && gb == 0 {
                state.g[0] = 1; // set GB
            } else if c2 == b'\n' && gb == 0 {
                // line-continuation
            } else if c2 == b'}' && gb == 1 {
                state.g[0] = 0; // set ASCII
            } else {
                return Stop::Illegal(1);
            }
            input.pos += 2;
            continue;
        }
        if c & 0x80 != 0 {
            return Stop::Illegal(1);
        }
        if state.g[0] == 0 {
            // ASCII mode.
            out.push(u32::from(c));
            input.pos += 1;
        } else {
            // GB mode.
            if input.left() < 2 {
                return Stop::TooFew;
            }
            match t::GB2312.get(c, input.at(1)) {
                Some(decoded) => {
                    out.push(decoded);
                    input.pos += 2;
                }
                None => return Stop::Illegal(1),
            }
        }
    }
    Stop::Done
}

// ------------------------------------------------------- _codecs_tw.c, _hk.c

fn big5(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        match t::BIG5.get(c, input.at(1)) {
            Some(decoded) => {
                out.push(decoded);
                input.pos += 2;
            }
            None => return Stop::Illegal(1),
        }
    }
    Stop::Done
}

fn cp950(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        match t::CP950EXT.get(c, c2).or_else(|| t::BIG5.get(c, c2)) {
            Some(decoded) => out.push(decoded),
            None => return Stop::Illegal(1),
        }
        input.pos += 2;
    }
    Stop::Done
}

/// `BH2S(c1, c2)`.
fn bh2s(c1: u8, c2: u8) -> i32 {
    (i32::from(c1) - 0x87) * (0xfe - 0x40 + 1) + (i32::from(c2) - 0x40)
}

fn big5hkscs(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        let big5 = if !(0xc6..=0xc8).contains(&c) || (c < 0xc7 && c2 < 0xa1) {
            t::BIG5.get(c, c2)
        } else {
            None
        };
        if let Some(decoded) = big5 {
            out.push(decoded);
            input.pos += 2;
            continue;
        }
        if let Some(decoded) = t::BIG5HKSCS.get(c, c2) {
            let mut s = bh2s(c, c2);
            let hintbase: &[u8] = if bh2s(0x87, 0x40) <= s && s <= bh2s(0xa0, 0xfe) {
                s -= bh2s(0x87, 0x40);
                t::BIG5HKSCS_PHINT_0
            } else if bh2s(0xc6, 0xa1) <= s && s <= bh2s(0xc8, 0xfe) {
                s -= bh2s(0xc6, 0xa1);
                t::BIG5HKSCS_PHINT_12130
            } else if bh2s(0xf9, 0xd6) <= s && s <= bh2s(0xfe, 0xfe) {
                s -= bh2s(0xf9, 0xd6);
                t::BIG5HKSCS_PHINT_21924
            } else {
                return Stop::Internal;
            };
            let hint = usize::try_from(s >> 3)
                .ok()
                .and_then(|i| hintbase.get(i))
                .copied()
                .unwrap_or(0);
            if hint & (1 << (s & 7)) != 0 {
                out.push(decoded | 0x20000);
            } else {
                out.push(decoded);
            }
            input.pos += 2;
            continue;
        }
        let pair = match (u16::from(c) << 8) | u16::from(c2) {
            0x8862 => [0x00ca, 0x0304],
            0x8864 => [0x00ca, 0x030c],
            0x88a3 => [0x00ea, 0x0304],
            0x88a5 => [0x00ea, 0x030c],
            _ => return Stop::Illegal(1),
        };
        out.extend(pair);
        input.pos += 2;
    }
    Stop::Done
}

// ------------------------------------------------------------ _codecs_kr.c

const EUCKR_JAMO_FIRSTBYTE: u8 = 0xA4;
const EUCKR_JAMO_FILLER: u8 = 0xD4;
/// `NONE` in the `cgk2u_*` section of `_codecs_kr.c`.
const KR_NONE: u8 = 127;

fn euc_kr(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        if c == EUCKR_JAMO_FIRSTBYTE && input.at(1) == EUCKR_JAMO_FILLER {
            // KS X 1001:1998 make-up sequence.
            if input.left() < 8 {
                return Stop::TooFew;
            }
            if input.at(2) != EUCKR_JAMO_FIRSTBYTE
                || input.at(4) != EUCKR_JAMO_FIRSTBYTE
                || input.at(6) != EUCKR_JAMO_FIRSTBYTE
            {
                return Stop::Illegal(1);
            }
            let c = input.at(3);
            let cho = if (0xa1..=0xbe).contains(&c) {
                t::CGK2U_CHOSEONG[usize::from(c - 0xa1)]
            } else {
                KR_NONE
            };
            let c = input.at(5);
            let jung = if (0xbf..=0xd3).contains(&c) {
                c - 0xbf
            } else {
                KR_NONE
            };
            let c = input.at(7);
            let jong = if c == EUCKR_JAMO_FILLER {
                0
            } else if (0xa1..=0xbe).contains(&c) {
                t::CGK2U_JONGSEONG[usize::from(c - 0xa1)]
            } else {
                KR_NONE
            };
            if cho == KR_NONE || jung == KR_NONE || jong == KR_NONE {
                return Stop::Illegal(1);
            }
            out.push(0xac00 + u32::from(cho) * 588 + u32::from(jung) * 28 + u32::from(jong));
            input.pos += 8;
        } else if let Some(decoded) = t::KSX1001.get(c ^ 0x80, input.at(1) ^ 0x80) {
            out.push(decoded);
            input.pos += 2;
        } else {
            return Stop::Illegal(1);
        }
    }
    Stop::Done
}

fn cp949(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        match t::KSX1001
            .get(c ^ 0x80, c2 ^ 0x80)
            .or_else(|| t::CP949EXT.get(c, c2))
        {
            Some(decoded) => out.push(decoded),
            None => return Stop::Illegal(1),
        }
        input.pos += 2;
    }
    Stop::Done
}

/// `FILL` and `NONE` in the johab section of `_codecs_kr.c`.
const JOHAB_FILL: u8 = 0xfd;
const JOHAB_NONE: u8 = 0xff;

fn johab(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        if c < 0xd8 {
            // johab hangul
            let c_cho = usize::from((c >> 2) & 0x1f);
            let c_jung = usize::from(((c << 3) | (c2 >> 5)) & 0x1f);
            let c_jong = usize::from(c2 & 0x1f);
            let i_cho = t::JOHABIDX_CHOSEONG[c_cho];
            let i_jung = t::JOHABIDX_JUNGSEONG[c_jung];
            let i_jong = t::JOHABIDX_JONGSEONG[c_jong];
            if i_cho == JOHAB_NONE || i_jung == JOHAB_NONE || i_jong == JOHAB_NONE {
                return Stop::Illegal(1);
            }
            // we don't use U+1100 hangul jamo yet.
            let decoded = if i_cho == JOHAB_FILL {
                if i_jung == JOHAB_FILL {
                    if i_jong == JOHAB_FILL {
                        0x3000
                    } else {
                        0x3100 | u32::from(t::JOHABJAMO_JONGSEONG[c_jong])
                    }
                } else if i_jong == JOHAB_FILL {
                    0x3100 | u32::from(t::JOHABJAMO_JUNGSEONG[c_jung])
                } else {
                    return Stop::Illegal(1);
                }
            } else if i_jung == JOHAB_FILL {
                if i_jong == JOHAB_FILL {
                    0x3100 | u32::from(t::JOHABJAMO_CHOSEONG[c_cho])
                } else {
                    return Stop::Illegal(1);
                }
            } else {
                0xac00
                    + u32::from(i_cho) * 588
                    + u32::from(i_jung) * 28
                    + if i_jong == JOHAB_FILL {
                        0
                    } else {
                        u32::from(i_jong)
                    }
            };
            out.push(decoded);
            input.pos += 2;
        } else {
            // KS X 1001 except hangul jamos and syllables
            if c == 0xdf
                || c > 0xf9
                || c2 < 0x31
                || (0x80..0x91).contains(&c2)
                || (c2 & 0x7f) == 0x7f
                || (c == 0xda && (0xa1..=0xd3).contains(&c2))
            {
                return Stop::Illegal(1);
            }
            // `unsigned char` arithmetic, which wraps.
            let mut t1: u8 = if c < 0xe0 {
                (c.wrapping_sub(0xd9)).wrapping_mul(2)
            } else {
                (2 * u32::from(c) - 0x197) as u8
            };
            let mut t2: u8 = if c2 < 0x91 { c2 - 0x31 } else { c2 - 0x43 };
            t1 = t1
                .wrapping_add(if t2 < 0x5e { 0 } else { 1 })
                .wrapping_add(0x21);
            t2 = (if t2 < 0x5e { t2 } else { t2 - 0x5e }) + 0x21;
            match t::KSX1001.get(t1, t2) {
                Some(decoded) => {
                    out.push(decoded);
                    input.pos += 2;
                }
                None => return Stop::Illegal(1),
            }
        }
    }
    Stop::Done
}

// ------------------------------------------------------------ _codecs_jp.c

/// The Shift_JIS lead/trail arithmetic shared by `cp932` and `shift_jis`
/// (`c1`/`c2` to a JIS X 0208 row/cell).
fn sjis_to_jis(c: u8, c2: u8) -> (u8, u8) {
    let c1 = if c < 0xe0 { c - 0x81 } else { c - 0xc1 };
    let c2 = if c2 < 0x80 { c2 - 0x40 } else { c2 - 0x41 };
    let c1 = 2 * c1 + if c2 < 0x5e { 0 } else { 1 } + 0x21;
    let c2 = (if c2 < 0x5e { c2 } else { c2 - 0x5e }) + 0x21;
    (c1, c2)
}

fn sjis_bad_trail(c2: u8) -> bool {
    c2 < 0x40 || (c2 > 0x7e && c2 < 0x80) || c2 > 0xfc
}

fn cp932(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c <= 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        } else if (0xa0..=0xdf).contains(&c) {
            if c == 0xa0 {
                out.push(0xf8f0); // half-width katakana
            } else {
                out.push(0xfec0 + u32::from(c));
            }
            input.pos += 1;
            continue;
        } else if c >= 0xfd {
            // Windows compatibility
            out.push(0xf8f1 - 0xfd + u32::from(c));
            input.pos += 1;
            continue;
        }
        if input.left() < 2 {
            return Stop::TooFew;
        }
        let c2 = input.at(1);
        if let Some(decoded) = t::CP932EXT.get(c, c2) {
            out.push(decoded);
        } else if (0x81..=0x9f).contains(&c) || (0xe0..=0xea).contains(&c) {
            if sjis_bad_trail(c2) {
                return Stop::Illegal(1);
            }
            let (c, c2) = sjis_to_jis(c, c2);
            match t::JISX0208.get(c, c2) {
                Some(decoded) => out.push(decoded),
                None => return Stop::Illegal(1),
            }
        } else if (0xf0..=0xf9).contains(&c) {
            if (0x40..=0x7e).contains(&c2) || (0x80..=0xfc).contains(&c2) {
                out.push(
                    0xe000
                        + 188 * u32::from(c - 0xf0)
                        + u32::from(if c2 < 0x80 { c2 - 0x40 } else { c2 - 0x41 }),
                );
            } else {
                return Stop::Illegal(1);
            }
        } else {
            return Stop::Illegal(1);
        }
        input.pos += 2;
    }
    Stop::Done
}

/// `EMULATE_JISX0213_2000_DECODE_PLANE1`'s rows that JIS X 0213:2000 lacks.
fn jisx0213_2000_plane1_invalid(c1: u8, c2: u8) -> bool {
    matches!(
        (c1, c2),
        (0x2E, 0x21)
            | (0x2F, 0x7E)
            | (0x4F, 0x54)
            | (0x4F, 0x7E)
            | (0x74, 0x27)
            | (0x7E, 0x7A)
            | (0x7E, 0x7B)
            | (0x7E, 0x7C)
            | (0x7E, 0x7D)
            | (0x7E, 0x7E)
    )
}

/// `EMULATE_JISX0213_2000_DECODE_INVALID` outside `_codecs_iso2022.c`.
const EMULATE_DECODE_INVALID: usize = 2;

fn euc_jis_2004(config_2000: bool, input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if c == 0x8e {
            // JIS X 0201 half-width katakana
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c2 = input.at(1);
            if (0xa1..=0xdf).contains(&c2) {
                out.push(0xfec0 + u32::from(c2));
                input.pos += 2;
            } else {
                return Stop::Illegal(1);
            }
        } else if c == 0x8f {
            if input.left() < 3 {
                return Stop::TooFew;
            }
            let c2 = input.at(1) ^ 0x80;
            let c3 = input.at(2) ^ 0x80;
            // JIS X 0213 Plane 2 or JIS X 0212 (see NOTES)
            if config_2000 && c2 == 0x7D && c3 == 0x3B {
                out.push(0x9B1D);
            } else if let Some(decoded) = t::JISX0213_2_BMP.get(c2, c3) {
                out.push(decoded);
            } else if let Some(code) = t::JISX0213_2_EMP.get(c2, c3) {
                out.push(EMPBASE | code);
                input.pos += 3;
                continue;
            } else if let Some(decoded) = t::JISX0212.get(c2, c3) {
                out.push(decoded);
            } else {
                return Stop::Illegal(1);
            }
            input.pos += 3;
        } else {
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c = c ^ 0x80;
            let c2 = input.at(1) ^ 0x80;
            // JIS X 0213 Plane 1
            if config_2000 && jisx0213_2000_plane1_invalid(c, c2) {
                return Stop::Illegal(EMULATE_DECODE_INVALID);
            } else if c == 0x21 && c2 == 0x40 {
                out.push(0xff3c);
            } else if c == 0x22 && c2 == 0x32 {
                out.push(0xff5e);
            } else if let Some(decoded) = t::JISX0208.get(c, c2) {
                out.push(decoded);
            } else if let Some(decoded) = t::JISX0213_1_BMP.get(c, c2) {
                out.push(decoded);
            } else if let Some(code) = t::JISX0213_1_EMP.get(c, c2) {
                out.push(EMPBASE | code);
                input.pos += 2;
                continue;
            } else if let Some(code) = t::JISX0213_PAIR.get(c, c2) {
                out.extend([code >> 16, code & 0xffff]);
                input.pos += 2;
                continue;
            } else {
                return Stop::Illegal(1);
            }
            input.pos += 2;
        }
    }
    Stop::Done
}

fn euc_jp(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
            input.pos += 1;
            continue;
        }
        if c == 0x8e {
            // JIS X 0201 half-width katakana
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c2 = input.at(1);
            if (0xa1..=0xdf).contains(&c2) {
                out.push(0xfec0 + u32::from(c2));
                input.pos += 2;
            } else {
                return Stop::Illegal(1);
            }
        } else if c == 0x8f {
            if input.left() < 3 {
                return Stop::TooFew;
            }
            // JIS X 0212
            match t::JISX0212.get(input.at(1) ^ 0x80, input.at(2) ^ 0x80) {
                Some(decoded) => {
                    out.push(decoded);
                    input.pos += 3;
                }
                None => return Stop::Illegal(1),
            }
        } else {
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c2 = input.at(1);
            // JIS X 0208
            if c == 0xa1 && c2 == 0xc0 {
                // FULL-WIDTH REVERSE SOLIDUS
                out.push(0xff3c);
            } else if let Some(decoded) = t::JISX0208.get(c ^ 0x80, c2 ^ 0x80) {
                out.push(decoded);
            } else {
                return Stop::Illegal(1);
            }
            input.pos += 2;
        }
    }
    Stop::Done
}

fn shift_jis(input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if c < 0x80 {
            out.push(u32::from(c));
        } else if (0xa1..=0xdf).contains(&c) {
            // JISX0201_K_DECODE
            out.push(0xfec0 + u32::from(c));
        } else if (0x81..=0x9f).contains(&c) || (0xe0..=0xea).contains(&c) {
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c2 = input.at(1);
            if sjis_bad_trail(c2) {
                return Stop::Illegal(1);
            }
            let (c1, c2) = sjis_to_jis(c, c2);
            if c1 == 0x21 && c2 == 0x40 {
                // FULL-WIDTH REVERSE SOLIDUS
                out.push(0xff3c);
                input.pos += 2;
                continue;
            }
            match t::JISX0208.get(c1, c2) {
                Some(decoded) => {
                    out.push(decoded);
                    input.pos += 2;
                    continue;
                }
                None => return Stop::Illegal(1),
            }
        } else {
            return Stop::Illegal(1);
        }
        input.pos += 1; // JIS X 0201
    }
    Stop::Done
}

/// `JISX0201_DECODE(c, writer)` (`alg_jisx0201.h`).
fn jisx0201_decode(c: u8) -> Option<u32> {
    match c {
        0..=0x5b | 0x5d..=0x7d | 0x7f => Some(u32::from(c)),
        0x5c => Some(0x00a5),
        0x7e => Some(0x203e),
        0xa1..=0xdf => Some(0xfec0 + u32::from(c)),
        _ => None,
    }
}

fn shift_jis_2004(config_2000: bool, input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if let Some(decoded) = jisx0201_decode(c) {
            out.push(decoded);
        } else if (0x81..=0x9f).contains(&c) || (0xe0..=0xfc).contains(&c) {
            if input.left() < 2 {
                return Stop::TooFew;
            }
            let c2 = input.at(1);
            if sjis_bad_trail(c2) {
                return Stop::Illegal(1);
            }
            let c1 = if c < 0xe0 { c - 0x81 } else { c - 0xc1 };
            let c2 = if c2 < 0x80 { c2 - 0x40 } else { c2 - 0x41 };
            let mut c1 = 2 * c1 + if c2 < 0x5e { 0 } else { 1 };
            let c2 = (if c2 < 0x5e { c2 } else { c2 - 0x5e }) + 0x21;
            if c1 < 0x5e {
                // Plane 1
                c1 += 0x21;
                if config_2000 && jisx0213_2000_plane1_invalid(c1, c2) {
                    return Stop::Illegal(EMULATE_DECODE_INVALID);
                } else if let Some(decoded) = t::JISX0208.get(c1, c2) {
                    out.push(decoded);
                } else if let Some(decoded) = t::JISX0213_1_BMP.get(c1, c2) {
                    out.push(decoded);
                } else if let Some(code) = t::JISX0213_1_EMP.get(c1, c2) {
                    out.push(EMPBASE | code);
                } else if let Some(code) = t::JISX0213_PAIR.get(c1, c2) {
                    out.extend([code >> 16, code & 0xffff]);
                } else {
                    return Stop::Illegal(1);
                }
                input.pos += 2;
            } else {
                // Plane 2
                if c1 >= 0x67 {
                    c1 += 0x07;
                } else if c1 >= 0x63 || c1 == 0x5f {
                    c1 -= 0x37;
                } else {
                    c1 -= 0x3d;
                }
                if config_2000 && c1 == 0x7D && c2 == 0x3B {
                    out.push(0x9B1D);
                } else if let Some(decoded) = t::JISX0213_2_BMP.get(c1, c2) {
                    out.push(decoded);
                } else if let Some(code) = t::JISX0213_2_EMP.get(c1, c2) {
                    out.push(EMPBASE | code);
                    input.pos += 2;
                    continue;
                } else {
                    return Stop::Illegal(1);
                }
                input.pos += 2;
            }
            continue;
        } else {
            return Stop::Illegal(1);
        }
        input.pos += 1; // JIS X 0201
    }
    Stop::Done
}

// ------------------------------------------------------- _codecs_iso2022.c

const ESC: u8 = 0x1B;
const SO: u8 = 0x0E;
const SI: u8 = 0x0F;
const LF: u8 = 0x0A;
const MAX_ESCSEQLEN: usize = 16;
const CHARSET_DBCS: u8 = 0x80;
const CHARSET_ISO8859_1: u8 = b'A';
const CHARSET_ASCII: u8 = b'B';
const CHARSET_ISO8859_7: u8 = b'F';
const MAP_UNMAPPABLE: u32 = 0xFFFF;
const F_SHIFTED: u8 = 0x01;
const F_ESCTHROUGHOUT: u8 = 0x02;
const NO_SHIFT: u8 = 0x01;
const USE_G2: u8 = 0x02;
const USE_JISX0208_EXT: u8 = 0x04;

/// A designation's decoder function.
#[derive(Clone, Copy)]
enum Dsg {
    Ksx1001,
    Jisx0201R,
    Jisx0201K,
    Jisx0208,
    Jisx0212,
    Jisx0213_2000_1,
    Jisx0213_2000_2,
    Jisx0213_2004_1,
    Jisx0213_2004_2,
    Gb2312,
    Dummy,
}

/// `struct iso2022_designation`: mark, width, decoder.
type Designation = (u8, usize, Dsg);

/// `struct iso2022_config`.
struct Iso2022Config {
    flags: u8,
    designations: &'static [Designation],
}

const KSX1001_G0: Designation = (b'C' | CHARSET_DBCS, 2, Dsg::Ksx1001);
const KSX1001_G1: Designation = (b'C' | CHARSET_DBCS, 2, Dsg::Ksx1001);
const JISX0201_R: Designation = (b'J', 1, Dsg::Jisx0201R);
const JISX0201_K: Designation = (b'I', 1, Dsg::Jisx0201K);
const JISX0208: Designation = (b'B' | CHARSET_DBCS, 2, Dsg::Jisx0208);
const JISX0208_O: Designation = (b'@' | CHARSET_DBCS, 2, Dsg::Jisx0208);
const JISX0212: Designation = (b'D' | CHARSET_DBCS, 2, Dsg::Jisx0212);
const JISX0213_2000_1: Designation = (b'O' | CHARSET_DBCS, 2, Dsg::Jisx0213_2000_1);
const JISX0213_2000_2: Designation = (b'P' | CHARSET_DBCS, 2, Dsg::Jisx0213_2000_2);
const JISX0213_2004_1: Designation = (b'Q' | CHARSET_DBCS, 2, Dsg::Jisx0213_2004_1);
const JISX0213_2004_2: Designation = (b'P' | CHARSET_DBCS, 2, Dsg::Jisx0213_2004_2);
const GB2312: Designation = (b'A' | CHARSET_DBCS, 2, Dsg::Gb2312);
const ISO8859_1: Designation = (CHARSET_ISO8859_1, 1, Dsg::Dummy);
const ISO8859_7: Designation = (CHARSET_ISO8859_7, 1, Dsg::Dummy);

fn iso2022_config(codec: Cjk) -> Option<&'static Iso2022Config> {
    static KR: Iso2022Config = Iso2022Config {
        flags: 0,
        designations: &[KSX1001_G1],
    };
    static JP: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_JISX0208_EXT,
        designations: &[JISX0208, JISX0201_R, JISX0208_O],
    };
    static JP_1: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_JISX0208_EXT,
        designations: &[JISX0208, JISX0212, JISX0201_R, JISX0208_O],
    };
    static JP_2: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_G2 | USE_JISX0208_EXT,
        designations: &[
            JISX0208, JISX0212, KSX1001_G0, GB2312, JISX0201_R, JISX0208_O, ISO8859_1, ISO8859_7,
        ],
    };
    // `REGISTRY_JISX0213_*_1_PAIRONLY` differs from `REGISTRY_JISX0213_*_1`
    // only in its encoder.
    static JP_2004: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_JISX0208_EXT,
        designations: &[JISX0213_2004_1, JISX0208, JISX0213_2004_1, JISX0213_2004_2],
    };
    static JP_3: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_JISX0208_EXT,
        designations: &[JISX0213_2000_1, JISX0208, JISX0213_2000_1, JISX0213_2000_2],
    };
    static JP_EXT: Iso2022Config = Iso2022Config {
        flags: NO_SHIFT | USE_JISX0208_EXT,
        designations: &[JISX0208, JISX0212, JISX0201_R, JISX0201_K, JISX0208_O],
    };
    Some(match codec {
        Cjk::Iso2022Kr => &KR,
        Cjk::Iso2022Jp => &JP,
        Cjk::Iso2022Jp1 => &JP_1,
        Cjk::Iso2022Jp2 => &JP_2,
        Cjk::Iso2022Jp2004 => &JP_2004,
        Cjk::Iso2022Jp3 => &JP_3,
        Cjk::Iso2022JpExt => &JP_EXT,
        _ => return None,
    })
}

/// `IS_ESCEND(c)`.
fn is_escend(c: u8) -> bool {
    c.is_ascii_uppercase() || c == b'@'
}

/// `iso2022processesc`: `Ok` advanced past the designation.
fn process_esc(config: &Iso2022Config, state: &mut State, input: &mut In) -> Result<(), Stop> {
    let inleft = input.left();
    let mut esclen = 0;
    let mut i = 1;
    while i < MAX_ESCSEQLEN {
        if i >= inleft {
            return Err(Stop::TooFew);
        }
        if is_escend(input.at(i)) {
            esclen = i + 1;
            break;
        } else if config.flags & USE_JISX0208_EXT != 0
            && i + 1 < inleft
            && input.at(i) == b'&'
            && input.at(i + 1) == b'@'
        {
            i += 2;
        }
        i += 1;
    }
    let (charset, designation) = match esclen {
        // unterminated escape sequence
        0 => return Err(Stop::Illegal(1)),
        3 => {
            if input.at(1) == b'$' {
                (input.at(2) | CHARSET_DBCS, 0)
            } else if input.at(1) == b'(' {
                (input.at(2), 0)
            } else if input.at(1) == b')' {
                (input.at(2), 1)
            } else if config.flags & USE_G2 != 0 && input.at(1) == b'.' {
                (input.at(2), 2)
            } else {
                return Err(Stop::Illegal(3));
            }
        }
        4 => {
            if input.at(1) != b'$' {
                return Err(Stop::Illegal(4));
            }
            let charset = input.at(3) | CHARSET_DBCS;
            match input.at(2) {
                b'(' => (charset, 0),
                b')' => (charset, 1),
                _ => return Err(Stop::Illegal(4)),
            }
        }
        // designation with prefix
        6 => {
            if config.flags & USE_JISX0208_EXT != 0
                && input.at(3) == ESC
                && input.at(4) == b'$'
                && input.at(5) == b'B'
            {
                (b'B' | CHARSET_DBCS, 0)
            } else {
                return Err(Stop::Illegal(6));
            }
        }
        _ => return Err(Stop::Illegal(esclen)),
    };
    // raise error when the charset is not designated for this encoding
    if charset != CHARSET_ASCII && !config.designations.iter().any(|d| d.0 == charset) {
        return Err(Stop::Illegal(esclen));
    }
    state.g[designation] = charset;
    input.pos += esclen;
    Ok(())
}

/// `ISO8859_7_DECODE(c, writer)`.
fn iso8859_7_decode(c: u8) -> Option<u32> {
    let bit = |mask: u32, shift: u8| mask.checked_shr(u32::from(shift)).unwrap_or(0) & 1 != 0;
    if c < 0xa0 || (c < 0xc0 && bit(0x288f_3bc9, c - 0xa0)) {
        Some(u32::from(c))
    } else if (0xb4..=0xfe).contains(&c) && (c >= 0xd4 || bit(0xbfff_fd77, c - 0xb4)) {
        Some(0x02d0 + u32::from(c))
    } else if c == 0xa1 {
        Some(0x2018)
    } else if c == 0xa2 {
        Some(0x2019)
    } else if c == 0xaf {
        Some(0x2015)
    } else {
        None
    }
}

/// `iso2022processg2`.
fn process_g2(state: &State, input: &mut In, out: &mut Text) -> Result<(), Stop> {
    let c3 = input.at(2);
    if state.g[2] == CHARSET_ISO8859_1 {
        if c3 < 0x80 {
            out.push(u32::from(c3) + 0x80);
        } else {
            return Err(Stop::Illegal(3));
        }
    } else if state.g[2] == CHARSET_ISO8859_7 {
        match iso8859_7_decode(c3 ^ 0x80) {
            Some(decoded) => out.push(decoded),
            None => return Err(Stop::Illegal(3)),
        }
    } else if state.g[2] == CHARSET_ASCII {
        if c3 & 0x80 != 0 {
            return Err(Stop::Illegal(3));
        }
        out.push(u32::from(c3));
    } else {
        return Err(Stop::Internal);
    }
    input.pos += 3;
    Ok(())
}

/// A designation's `decoder(codec, data)`.
fn dsg_decode(dsg: Dsg, d0: u8, d1: u8) -> u32 {
    let jisx0213_1 = |emulate_2000: bool| {
        if emulate_2000 && jisx0213_2000_plane1_invalid(d0, d1) {
            MAP_UNMAPPABLE
        } else if d0 == 0x21 && d1 == 0x40 {
            // F/W REVERSE SOLIDUS
            0xff3c
        } else if let Some(u) = t::JISX0208.get(d0, d1) {
            u
        } else if let Some(u) = t::JISX0213_1_BMP.get(d0, d1) {
            u
        } else if let Some(u) = t::JISX0213_1_EMP.get(d0, d1) {
            u | 0x20000
        } else if let Some(u) = t::JISX0213_PAIR.get(d0, d1) {
            u
        } else {
            MAP_UNMAPPABLE
        }
    };
    // `jisx0213_2000_2_decoder` assigns 0x9B1D for (0x7D, 0x3B) and then
    // overwrites it with the plane 2 lookups, so it has no effect.
    let jisx0213_2 = || {
        if let Some(u) = t::JISX0213_2_BMP.get(d0, d1) {
            u
        } else if let Some(u) = t::JISX0213_2_EMP.get(d0, d1) {
            u | 0x20000
        } else {
            MAP_UNMAPPABLE
        }
    };
    match dsg {
        Dsg::Ksx1001 => t::KSX1001.get(d0, d1).unwrap_or(MAP_UNMAPPABLE),
        Dsg::Jisx0208 => {
            if d0 == 0x21 && d1 == 0x40 {
                // F/W REVERSE SOLIDUS
                0xff3c
            } else {
                t::JISX0208.get(d0, d1).unwrap_or(MAP_UNMAPPABLE)
            }
        }
        Dsg::Jisx0212 => t::JISX0212.get(d0, d1).unwrap_or(MAP_UNMAPPABLE),
        Dsg::Jisx0213_2000_1 => jisx0213_1(true),
        Dsg::Jisx0213_2004_1 => jisx0213_1(false),
        Dsg::Jisx0213_2000_2 | Dsg::Jisx0213_2004_2 => jisx0213_2(),
        Dsg::Jisx0201R => match d0 {
            0..=0x5b | 0x5d..=0x7d | 0x7f => u32::from(d0),
            0x5c => 0x00a5,
            0x7e => 0x203e,
            _ => MAP_UNMAPPABLE,
        },
        Dsg::Jisx0201K => {
            let c = d0 ^ 0x80;
            if (0xa1..=0xdf).contains(&c) {
                0xfec0 + u32::from(c)
            } else {
                MAP_UNMAPPABLE
            }
        }
        Dsg::Gb2312 => t::GB2312.get(d0, d1).unwrap_or(MAP_UNMAPPABLE),
        Dsg::Dummy => MAP_UNMAPPABLE,
    }
}

fn iso2022(config: &Iso2022Config, state: &mut State, input: &mut In, out: &mut Text) -> Stop {
    while input.left() > 0 {
        let c = input.at(0);
        if state.flags & F_ESCTHROUGHOUT != 0 {
            // ESC throughout mode: for non-iso2022 escape sequences
            out.push(u32::from(c)); // assume as ISO-8859-1
            input.pos += 1;
            if is_escend(c) {
                state.flags &= !F_ESCTHROUGHOUT;
            }
            continue;
        }
        let bypass = match c {
            ESC => {
                if input.left() < 2 {
                    return Stop::TooFew;
                }
                let c2 = input.at(1);
                if matches!(c2, b'(' | b')' | b'$' | b'.' | b'&') {
                    if let Err(stop) = process_esc(config, state, input) {
                        return stop;
                    }
                } else if config.flags & USE_G2 != 0 && c2 == b'N' {
                    // SS2
                    if input.left() < 3 {
                        return Stop::TooFew;
                    }
                    if let Err(stop) = process_g2(state, input, out) {
                        return stop;
                    }
                } else {
                    out.push(u32::from(ESC));
                    state.flags |= F_ESCTHROUGHOUT;
                    input.pos += 1;
                }
                false
            }
            SI if config.flags & NO_SHIFT == 0 => {
                state.flags &= !F_SHIFTED;
                input.pos += 1;
                false
            }
            SO if config.flags & NO_SHIFT == 0 => {
                state.flags |= F_SHIFTED;
                input.pos += 1;
                false
            }
            SI | SO => true,
            LF => {
                state.flags &= !F_SHIFTED;
                out.push(u32::from(LF));
                input.pos += 1;
                false
            }
            _ if c < 0x20 => true,
            _ if c >= 0x80 => return Stop::Illegal(1),
            _ => {
                let charset = if state.flags & F_SHIFTED != 0 {
                    state.g[1]
                } else {
                    state.g[0]
                };
                if charset == CHARSET_ASCII {
                    true
                } else {
                    let Some(&(_, width, dsg)) =
                        config.designations.iter().find(|d| d.0 == charset)
                    else {
                        return Stop::Internal;
                    };
                    if input.left() < width {
                        return Stop::TooFew;
                    }
                    let decoded = dsg_decode(dsg, input.at(0), input.at(1));
                    if decoded == MAP_UNMAPPABLE {
                        return Stop::Illegal(width);
                    }
                    if decoded < 0x30000 {
                        out.push(decoded);
                    } else {
                        // JIS X 0213 pairs
                        out.extend([decoded >> 16, decoded & 0xffff]);
                    }
                    input.pos += width;
                    false
                }
            }
        };
        if bypass {
            out.push(u32::from(c));
            input.pos += 1;
        }
    }
    Stop::Done
}
