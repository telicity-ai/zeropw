//! The app icon, the Personal Vault mark (desktop/src/ui/icons.tsx `Mark`): a rounded vault door
//! and its dial drawn in ink on a warm paper tile, with one pine dot at the centre (DESIGN.md
//! §2.1). A minimal PNG encoder (8-bit RGBA, stored deflate blocks, CRC-32, Adler-32) keeps the
//! build free of committed images and extra dependencies. Used by build.rs; the tests run in
//! the app crate.

/// Samples per pixel side for anti-aliasing.
const SUPERSAMPLE: u32 = 4;
/// Warm paper tile (`--paper-1`).
const PAPER: [f64; 3] = [245.0, 242.0, 236.0];
/// Ink (`--ink-1`).
const INK: [f64; 3] = [29.0, 26.0, 21.0];
/// Pine accent (`--pine-1`).
const PINE: [f64; 3] = [39.0, 95.0, 79.0];

/// Distance from (px, py) to a rounded square centred at (c, c) with half side `half` and
/// corner radius `r` (negative inside).
fn rounded_square(px: f64, py: f64, c: f64, half: f64, r: f64) -> f64 {
    let qx = (px - c).abs() - (half - r);
    let qy = (py - c).abs() - (half - r);
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    outside + qx.max(qy).min(0.0) - r
}

/// What the mark paints at a point of a tile of side `tile` starting at `inset`, or None for
/// the bare paper.
fn mark_color(px: f64, py: f64, inset: f64, tile: f64) -> Option<[f64; 3]> {
    let c = inset + tile / 2.0;
    let stroke = tile * 0.052;
    let door_half = tile * 0.30;
    let door = rounded_square(px, py, c, door_half, door_half * 0.30);
    let d = ((px - c).powi(2) + (py - c).powi(2)).sqrt();
    let dial = (d - tile * 0.12).abs();
    if d <= tile * 0.048 {
        Some(PINE)
    } else if door.abs() <= stroke / 2.0 || dial <= stroke / 2.0 {
        Some(INK)
    } else {
        None
    }
}

/// The icon as `size`×`size` RGBA pixels (straight alpha).
pub fn icon_rgba(size: u32) -> Vec<u8> {
    let s = f64::from(size);
    // macOS icon grid: a rounded tile inset 100/1024 on each side.
    let inset = s * 100.0 / 1024.0;
    let tile = s - 2.0 * inset;
    let radius = tile * 0.2237;
    let mut out = vec![0u8; (size * size * 4) as usize];
    let n = f64::from(SUPERSAMPLE);
    for y in 0..size {
        for x in 0..size {
            let mut sum = [0.0f64; 3];
            let mut covered = 0.0f64;
            for sy in 0..SUPERSAMPLE {
                for sx in 0..SUPERSAMPLE {
                    let px = f64::from(x) + (f64::from(sx) + 0.5) / n;
                    let py = f64::from(y) + (f64::from(sy) + 0.5) / n;
                    if rounded_square(px, py, s / 2.0, tile / 2.0, radius) > 0.0 {
                        continue;
                    }
                    let color = mark_color(px, py, inset, tile).unwrap_or(PAPER);
                    for (acc, c) in sum.iter_mut().zip(color) {
                        *acc += c;
                    }
                    covered += 1.0;
                }
            }
            let i = ((y * size + x) * 4) as usize;
            if covered > 0.0 {
                for (channel, total) in out[i..i + 3].iter_mut().zip(sum) {
                    *channel = (total / covered).round() as u8;
                }
                out[i + 3] = (covered / (n * n) * 255.0).round() as u8;
            }
        }
    }
    out
}

/// The icon as a PNG file.
pub fn icon_png(size: u32) -> Vec<u8> {
    encode_rgba(size, size, &icon_rgba(size))
}

/// An 8-bit RGBA PNG with one IDAT of stored (uncompressed) deflate blocks.
pub fn encode_rgba(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let stride = width as usize * 4;
    assert_eq!(rgba.len(), stride * height as usize, "pixel buffer size");
    let mut raw = Vec::with_capacity((stride + 1) * height as usize);
    for row in rgba.chunks(stride.max(1)).take(height as usize) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }

    let mut zlib = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(0xFFFF).collect();
    if blocks.is_empty() {
        zlib.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    }
    for (n, block) in blocks.iter().enumerate() {
        zlib.push(u8::from(n + 1 == blocks.len()));
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, RGBA, deflate, adaptive, no interlace

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &zlib);
    chunk(&mut png, b"IEND", &[]);
    png
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = png.len();
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    let crc = crc32(&png[start..]);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// CRC-32 (ISO-HDLC, as PNG uses it).
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Adler-32 (zlib trailer).
pub fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_reference_values() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
        // Long input exercises the deferred modulo.
        let long = vec![0xFFu8; 100_000];
        let (mut a, mut b) = (1u64, 0u64);
        for &x in &long {
            a = (a + u64::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(adler32(&long), ((b << 16) | a) as u32);
    }

    /// Walk the chunks (checking every CRC) and undo the stored deflate blocks.
    fn decode(png: &[u8]) -> (u32, u32, Vec<u8>) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let mut at = 8;
        let (mut width, mut height, mut idat) = (0, 0, Vec::new());
        let mut kinds = Vec::new();
        while at < png.len() {
            let len = u32::from_be_bytes(png[at..at + 4].try_into().unwrap()) as usize;
            let kind = &png[at + 4..at + 8];
            let data = &png[at + 8..at + 8 + len];
            let crc = u32::from_be_bytes(png[at + 8 + len..at + 12 + len].try_into().unwrap());
            assert_eq!(crc, crc32(&png[at + 4..at + 8 + len]), "chunk CRC");
            match kind {
                b"IHDR" => {
                    width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                    height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                    assert_eq!(&data[8..], &[8, 6, 0, 0, 0]);
                }
                b"IDAT" => idat.extend_from_slice(data),
                _ => {}
            }
            kinds.push(String::from_utf8(kind.to_vec()).unwrap());
            at += 12 + len;
        }
        assert_eq!(kinds, ["IHDR", "IDAT", "IEND"]);
        assert_eq!(&idat[..2], &[0x78, 0x01]);
        assert_eq!(
            u16::from_be_bytes([idat[0], idat[1]]) % 31,
            0,
            "zlib header check bits"
        );
        let mut raw = Vec::new();
        let mut i = 2;
        loop {
            let last = idat[i] & 1 == 1;
            assert_eq!(idat[i] >> 1, 0, "stored block");
            let len = u16::from_le_bytes([idat[i + 1], idat[i + 2]]);
            let nlen = u16::from_le_bytes([idat[i + 3], idat[i + 4]]);
            assert_eq!(nlen, !len);
            raw.extend_from_slice(&idat[i + 5..i + 5 + len as usize]);
            i += 5 + len as usize;
            if last {
                break;
            }
        }
        assert_eq!(
            u32::from_be_bytes(idat[i..i + 4].try_into().unwrap()),
            adler32(&raw)
        );
        assert_eq!(i + 4, idat.len());
        let stride = width as usize * 4 + 1;
        let mut pixels = Vec::new();
        for row in raw.chunks(stride) {
            assert_eq!(row[0], 0, "filter byte");
            pixels.extend_from_slice(&row[1..]);
        }
        (width, height, pixels)
    }

    #[test]
    fn encoded_images_round_trip() {
        let pixels: Vec<u8> = (0..2 * 3 * 4).map(|i| i as u8).collect();
        let (w, h, back) = decode(&encode_rgba(2, 3, &pixels));
        assert_eq!((w, h), (2, 3));
        assert_eq!(back, pixels);
        // More than one stored block (65535-byte limit).
        let big: Vec<u8> = (0..200 * 200 * 4).map(|i| (i % 251) as u8).collect();
        let (_, _, back) = decode(&encode_rgba(200, 200, &big));
        assert_eq!(back, big);
    }

    #[test]
    fn icons_are_the_vault_mark_on_a_paper_tile() {
        for size in [32u32, 128, 512] {
            let png = icon_png(size);
            assert!(!png.is_empty());
            let (w, h, px) = decode(&png);
            assert_eq!((w, h), (size, size));
            let at = |x: u32, y: u32| {
                let i = ((y * size + x) * 4) as usize;
                [px[i], px[i + 1], px[i + 2], px[i + 3]]
            };
            assert_eq!(at(0, 0)[3], 0, "corner is transparent");
            assert_eq!(at(size - 1, size - 1)[3], 0);
            let center = at(size / 2, size / 2);
            assert_eq!(center[3], 255);
            if size >= 128 {
                // the pine dot at the centre
                for (got, want) in center[..3].iter().zip([39u8, 95, 79]) {
                    assert!(got.abs_diff(want) <= 6, "{center:?}");
                }
                // inside the tile, outside the door: bare paper
                assert_eq!(at(size / 2, size * 15 / 100), [245, 242, 236, 255]);
                // the door's top edge is ink
                let edge = (0..size / 2)
                    .map(|y| at(size / 2, y))
                    .find(|p| p[0] < 80 && p[3] == 255);
                assert!(edge.is_some(), "no ink on the centre column above the dial");
            }
        }
    }
}
