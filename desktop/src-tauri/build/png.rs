//! The app icon, drawn from the pixel logo (the 9×9 slashed zero of desktop/src/lib/sigil.ts)
//! with an azure→iris gradient on a dark rounded square, and a minimal PNG encoder (8-bit
//! RGBA, stored deflate blocks, CRC-32, Adler-32) so no image is committed and the build has
//! no extra dependency. Used by build.rs; the tests run in the app crate.

/// Pixels per side of the logo grid.
const GRID: usize = 9;
/// Samples per pixel side for anti-aliasing.
const SUPERSAMPLE: u32 = 4;
/// Dark tile behind the logo (a lifted `--void`, DESIGN.md §2.1).
const TILE: [f64; 3] = [11.0, 11.0, 16.0];
/// `--grad`: azure → #7a7cff → iris (DESIGN.md §2.1).
const GRADIENT: [[f64; 3]; 3] = [
    [91.0, 140.0, 255.0],
    [122.0, 124.0, 255.0],
    [154.0, 107.0, 255.0],
];

/// The ring-and-slash logo, `[y][x]`, exactly as `logoCells()` draws it in the webview.
pub fn logo_cells() -> [[bool; GRID]; GRID] {
    let mut cells = [[false; GRID]; GRID];
    for (y, row) in cells.iter_mut().enumerate() {
        for (x, cell) in row.iter_mut().enumerate() {
            let (fx, fy) = (x as f64 - 4.0, y as f64 - 4.0);
            let d = (fx * fx + fy * fy).sqrt();
            *cell = (d - 3.6).abs() < 0.62 || (x + y == 8 && d < 3.2);
        }
    }
    cells
}

fn gradient(t: f64) -> [f64; 3] {
    let t = t.clamp(0.0, 1.0) * 2.0;
    let (a, b, f) = if t < 1.0 {
        (GRADIENT[0], GRADIENT[1], t)
    } else {
        (GRADIENT[1], GRADIENT[2], t - 1.0)
    };
    [
        a[0] + (b[0] - a[0]) * f,
        a[1] + (b[1] - a[1]) * f,
        a[2] + (b[2] - a[2]) * f,
    ]
}

/// The icon as `size`×`size` RGBA pixels (straight alpha).
pub fn icon_rgba(size: u32) -> Vec<u8> {
    let s = f64::from(size);
    // macOS icon grid: a rounded tile inset 100/1024 on each side.
    let inset = s * 100.0 / 1024.0;
    let tile = s - 2.0 * inset;
    let radius = tile * 0.2237;
    let logo = tile * 0.58;
    let cell = logo / GRID as f64;
    let origin = (s - logo) / 2.0;
    let cells = logo_cells();
    let inside_tile = |px: f64, py: f64| {
        let dx = (inset + radius - px)
            .max(px - (inset + tile - radius))
            .max(0.0);
        let dy = (inset + radius - py)
            .max(py - (inset + tile - radius))
            .max(0.0);
        px >= inset
            && px <= inset + tile
            && py >= inset
            && py <= inset + tile
            && dx * dx + dy * dy <= radius * radius
    };

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
                    if !inside_tile(px, py) {
                        continue;
                    }
                    let (cx, cy) = ((px - origin) / cell, (py - origin) / cell);
                    let on_logo = (0.0..GRID as f64).contains(&cx)
                        && (0.0..GRID as f64).contains(&cy)
                        && cells[cy as usize][cx as usize];
                    let color = if on_logo {
                        gradient((cx + cy) / (2.0 * GRID as f64))
                    } else {
                        TILE
                    };
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
    fn the_logo_is_the_slashed_zero() {
        let cells = logo_cells();
        assert!(cells[4][4], "the slash crosses the center");
        assert!(
            cells[0][4] && cells[4][0] && cells[8][4] && cells[4][8],
            "the ring"
        );
        assert!(!cells[0][0] && !cells[8][8] && !cells[2][2]);
        assert!(
            cells[2][6] && cells[6][2],
            "the slash runs bottom-left to top-right"
        );
        for (y, row) in cells.iter().enumerate() {
            for (x, cell) in row.iter().enumerate() {
                assert_eq!(*cell, cells[x][y], "symmetric about the slash");
            }
        }
    }

    #[test]
    fn icons_have_transparent_corners_and_a_gradient_logo() {
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
                // The middle of the slash is the middle of the gradient (#7a7cff).
                for (got, want) in center[..3].iter().zip([122u8, 124, 255]) {
                    assert!(got.abs_diff(want) <= 6, "{center:?}");
                }
                // Inside the tile, off the logo: the dark tile.
                let tile = at(size / 2, size * 15 / 100);
                assert_eq!(tile, [11, 11, 16, 255]);
            }
        }
    }
}
