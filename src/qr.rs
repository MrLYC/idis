//! Zero-dependency ISO/IEC 18004 QR Code encoder (Byte mode, ECC Level L, Versions 1..=10)
//! supporting both compact ANSI terminal rendering and crisp inline SVG output.

use anyhow::{anyhow, Result};

struct VersionSpec {
    version: usize,
    total_data_codewords: usize,
    ec_per_block: usize,
    g1_blocks: usize,
    g1_data_len: usize,
    g2_blocks: usize,
    g2_data_len: usize,
    align_centers: &'static [usize],
}

// ISO/IEC 18004 Table 9 (Error Correction Level L, Versions 1..=10, up to 271 bytes).
const VERSION_SPECS_L: &[VersionSpec] = &[
    VersionSpec {
        version: 1,
        total_data_codewords: 19,
        ec_per_block: 7,
        g1_blocks: 1,
        g1_data_len: 19,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[],
    },
    VersionSpec {
        version: 2,
        total_data_codewords: 34,
        ec_per_block: 10,
        g1_blocks: 1,
        g1_data_len: 34,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 18],
    },
    VersionSpec {
        version: 3,
        total_data_codewords: 55,
        ec_per_block: 15,
        g1_blocks: 1,
        g1_data_len: 55,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 22],
    },
    VersionSpec {
        version: 4,
        total_data_codewords: 80,
        ec_per_block: 20,
        g1_blocks: 1,
        g1_data_len: 80,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 26],
    },
    VersionSpec {
        version: 5,
        total_data_codewords: 108,
        ec_per_block: 26,
        g1_blocks: 1,
        g1_data_len: 108,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 30],
    },
    VersionSpec {
        version: 6,
        total_data_codewords: 136,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data_len: 68,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 34],
    },
    VersionSpec {
        version: 7,
        total_data_codewords: 156,
        ec_per_block: 20,
        g1_blocks: 2,
        g1_data_len: 78,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 22, 38],
    },
    VersionSpec {
        version: 8,
        total_data_codewords: 194,
        ec_per_block: 24,
        g1_blocks: 2,
        g1_data_len: 97,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 24, 42],
    },
    VersionSpec {
        version: 9,
        total_data_codewords: 232,
        ec_per_block: 30,
        g1_blocks: 2,
        g1_data_len: 116,
        g2_blocks: 0,
        g2_data_len: 0,
        align_centers: &[6, 26, 46],
    },
    VersionSpec {
        version: 10,
        total_data_codewords: 274,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data_len: 68,
        g2_blocks: 2,
        g2_data_len: 69,
        align_centers: &[6, 28, 50],
    },
];

/// Encoded QR Code matrix (`true` = dark module, `false` = light module).
#[derive(Debug, Clone)]
pub struct QrCode {
    size: usize,
    modules: Vec<bool>,
}

impl QrCode {
    /// Encode a UTF-8 string into a standard QR Code (Byte mode, ECC Level L).
    pub fn encode(text: &str) -> Result<Self> {
        let bytes = text.as_bytes();
        // Byte mode header overhead: Versions 1..=9 use 4 mode + 8 len = 2 bytes;
        // Version 10+ uses 4 mode + 16 len = 3 bytes (rounded up to full codewords).
        let spec = VERSION_SPECS_L
            .iter()
            .find(|s| {
                let overhead = if s.version <= 9 { 2 } else { 3 };
                bytes.len() + overhead <= s.total_data_codewords
            })
            .ok_or_else(|| {
                anyhow!(
                    "QR payload too long ({} bytes, max 271 bytes)",
                    bytes.len()
                )
            })?;

        let data_codewords =
            build_byte_mode_codewords(bytes, spec.version, spec.total_data_codewords);
        let all_codewords = add_ecc_and_interleave(&data_codewords, spec);

        let size = spec.version * 4 + 17;
        let mut base = vec![false; size * size];
        let mut is_fn = vec![false; size * size];

        draw_function_patterns(size, spec.version, spec.align_centers, &mut base, &mut is_fn);
        draw_codewords(size, &all_codewords, &mut base, &is_fn);

        // Pick best mask pattern (0..8) by ISO/IEC 18004 penalty score.
        let mut best_mask = 0u16;
        let mut best_penalty = u32::MAX;
        let mut best_modules = Vec::new();
        for mask in 0u16..8 {
            let mut candidate = base.clone();
            apply_mask(size, mask, &mut candidate, &is_fn);
            draw_format_bits(size, mask, &mut candidate);
            let penalty = compute_penalty(size, &candidate);
            if penalty < best_penalty {
                best_penalty = penalty;
                best_mask = mask;
                best_modules = candidate;
            }
        }
        let _ = best_mask;

        Ok(Self {
            size,
            modules: best_modules,
        })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn get(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    /// Render the QR code as a compact, high-contrast ANSI Unicode half-block block for terminals.
    ///
    /// Forces explicit white background + black foreground (`\x1b[47;30m`) with an ISO/IEC 18004
    /// 4-module quiet zone so the QR code scans reliably on both dark and light terminal themes.
    pub fn to_terminal_string(&self) -> String {
        let border = 4usize;
        let total = self.size + border * 2;
        let is_dark = |x: usize, y: usize| -> bool {
            if x < border || y < border || x >= border + self.size || y >= border + self.size {
                false
            } else {
                self.get(x - border, y - border)
            }
        };

        let mut out = String::new();
        let mut y = 0;
        while y < total {
            out.push_str("\x1b[47;30m");
            for x in 0..total {
                let top = is_dark(x, y);
                let bottom = if y + 1 < total {
                    is_dark(x, y + 1)
                } else {
                    false
                };
                let ch = match (top, bottom) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                };
                out.push(ch);
            }
            out.push_str("\x1b[0m\n");
            y += 2;
        }
        out
    }

    /// Render the QR code as a crisp, self-contained inline SVG string (4-module quiet zone).
    pub fn to_svg(&self) -> String {
        let border = 4usize;
        let total = self.size + border * 2;
        let mut path = String::new();
        for y in 0..self.size {
            for x in 0..self.size {
                if self.get(x, y) {
                    let px = x + border;
                    let py = y + border;
                    path.push_str(&format!("M{px},{py}h1v1h-1z"));
                }
            }
        }
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" shape-rendering="crispEdges"><rect width="{total}" height="{total}" fill="#ffffff"/><path d="{path}" fill="#000000"/></svg>"##
        )
    }
}

fn build_byte_mode_codewords(bytes: &[u8], version: usize, total_data_codewords: usize) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::with_capacity(total_data_codewords * 8);
    let push_bits = |buf: &mut Vec<bool>, val: u32, count: usize| {
        for i in (0..count).rev() {
            buf.push(((val >> i) & 1) != 0);
        }
    };

    // Mode indicator: Byte (0100) + 8-bit count (V1..=9) or 16-bit count (V10+).
    push_bits(&mut bits, 0b0100, 4);
    push_bits(&mut bits, bytes.len() as u32, if version <= 9 { 8 } else { 16 });
    for &b in bytes {
        push_bits(&mut bits, b as u32, 8);
    }

    // Terminator (up to 4 zero bits) + zero-pad to byte boundary.
    let target_bits = total_data_codewords * 8;
    let term_len = (target_bits - bits.len()).min(4);
    bits.resize(bits.len() + term_len, false);
    let pad_bits = (8 - (bits.len() & 7)) & 7;
    bits.resize(bits.len() + pad_bits, false);

    let mut codewords = Vec::with_capacity(total_data_codewords);
    for i in (0..bits.len()).step_by(8) {
        let mut b = 0u8;
        for &bit in &bits[i..i + 8] {
            b = (b << 1) | u8::from(bit);
        }
        codewords.push(b);
    }

    let mut pad_idx = 0usize;
    while codewords.len() < total_data_codewords {
        codewords.push(if (pad_idx & 1) == 0 { 0xEC } else { 0x11 });
        pad_idx += 1;
    }
    codewords
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    res
}

fn rs_generator_poly(degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0u8; poly.len() + 1];
        for (i, &c) in poly.iter().enumerate() {
            next[i] ^= c;
            next[i + 1] ^= gf_mul(c, root);
        }
        poly = next;
        root = gf_mul(root, 2);
    }
    poly
}

fn rs_compute_remainder(data: &[u8], gen: &[u8]) -> Vec<u8> {
    let ec_len = gen.len() - 1;
    let mut rem = vec![0u8; ec_len];
    for &b in data {
        let factor = b ^ rem[0];
        rem.copy_within(1.., 0);
        rem[ec_len - 1] = 0;
        for j in 0..ec_len {
            rem[j] ^= gf_mul(gen[j + 1], factor);
        }
    }
    rem
}

fn add_ecc_and_interleave(data: &[u8], spec: &VersionSpec) -> Vec<u8> {
    let gen = rs_generator_poly(spec.ec_per_block);
    let total_blocks = spec.g1_blocks + spec.g2_blocks;
    let mut data_blocks: Vec<&[u8]> = Vec::with_capacity(total_blocks);
    let mut ecc_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);

    let mut offset = 0usize;
    for _ in 0..spec.g1_blocks {
        let slice = &data[offset..offset + spec.g1_data_len];
        offset += spec.g1_data_len;
        data_blocks.push(slice);
        ecc_blocks.push(rs_compute_remainder(slice, &gen));
    }
    for _ in 0..spec.g2_blocks {
        let slice = &data[offset..offset + spec.g2_data_len];
        offset += spec.g2_data_len;
        data_blocks.push(slice);
        ecc_blocks.push(rs_compute_remainder(slice, &gen));
    }

    let max_data_len = spec.g1_data_len.max(spec.g2_data_len);
    let mut out =
        Vec::with_capacity(spec.total_data_codewords + spec.ec_per_block * total_blocks);
    for i in 0..max_data_len {
        for blk in &data_blocks {
            if let Some(&b) = blk.get(i) {
                out.push(b);
            }
        }
    }
    for i in 0..spec.ec_per_block {
        for blk in &ecc_blocks {
            out.push(blk[i]);
        }
    }
    out
}

fn set_fn(size: usize, x: usize, y: usize, dark: bool, mods: &mut [bool], is_fn: &mut [bool]) {
    mods[y * size + x] = dark;
    is_fn[y * size + x] = true;
}

fn draw_finder(size: usize, ox: isize, oy: isize, mods: &mut [bool], is_fn: &mut [bool]) {
    for dy in -1..=7 {
        for dx in -1..=7 {
            let x = ox + dx;
            let y = oy + dy;
            if x < 0 || y < 0 || x >= size as isize || y >= size as isize {
                continue;
            }
            let dark = (0..=6).contains(&dx)
                && (0..=6).contains(&dy)
                && (dx == 0
                    || dx == 6
                    || dy == 0
                    || dy == 6
                    || ((2..=4).contains(&dx) && (2..=4).contains(&dy)));
            set_fn(size, x as usize, y as usize, dark, mods, is_fn);
        }
    }
}

fn draw_alignment(size: usize, cx: usize, cy: usize, mods: &mut [bool], is_fn: &mut [bool]) {
    for dy in -2isize..=2 {
        for dx in -2isize..=2 {
            let dist = dx.abs().max(dy.abs());
            let dark = dist != 1;
            set_fn(
                size,
                (cx as isize + dx) as usize,
                (cy as isize + dy) as usize,
                dark,
                mods,
                is_fn,
            );
        }
    }
}

fn version_info_bits(version: usize) -> u32 {
    let data = (version as u32) & 0x3F;
    let mut rem = data << 12;
    for i in (0..6).rev() {
        if (rem & (1 << (i + 12))) != 0 {
            rem ^= 0x1F25 << i;
        }
    }
    (data << 12) | rem
}

fn draw_function_patterns(
    size: usize,
    version: usize,
    align_centers: &[usize],
    mods: &mut [bool],
    is_fn: &mut [bool],
) {
    // Timing patterns (row 6 and col 6).
    for i in 0..size {
        set_fn(size, i, 6, (i & 1) == 0, mods, is_fn);
        set_fn(size, 6, i, (i & 1) == 0, mods, is_fn);
    }

    // Three 7x7 finder patterns + white separators.
    draw_finder(size, 0, 0, mods, is_fn);
    draw_finder(size, (size - 7) as isize, 0, mods, is_fn);
    draw_finder(size, 0, (size - 7) as isize, mods, is_fn);

    // Alignment patterns (skipping corners overlapping finder patterns).
    for &cy in align_centers {
        for &cx in align_centers {
            let overlaps_finder = (cx <= 8 && cy <= 8)
                || (cx >= size - 9 && cy <= 8)
                || (cx <= 8 && cy >= size - 9);
            if !overlaps_finder {
                draw_alignment(size, cx, cy, mods, is_fn);
            }
        }
    }

    // Reserve format information cells (written after mask selection).
    for i in 0..=8 {
        is_fn[i * size + 8] = true;
        is_fn[8 * size + i] = true;
    }
    for i in 0..8 {
        is_fn[8 * size + (size - 1 - i)] = true;
    }
    for i in 0..7 {
        is_fn[(size - 1 - i) * size + 8] = true;
    }

    // Version information blocks for Version >= 7 (ISO/IEC 18004 Section 7.10).
    if version >= 7 {
        let vbits = version_info_bits(version);
        for i in 0..18 {
            let dark = ((vbits >> i) & 1) != 0;
            let a = size - 11 + (i % 3);
            let b = i / 3;
            set_fn(size, a, b, dark, mods, is_fn);
            set_fn(size, b, a, dark, mods, is_fn);
        }
    }

    // Fixed dark module at (8, size - 8).
    set_fn(size, 8, size - 8, true, mods, is_fn);
}

fn draw_codewords(size: usize, codewords: &[u8], mods: &mut [bool], is_fn: &[bool]) {
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut upward = true;
    let mut right = size as isize - 1;

    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for step in 0..size {
            let y = if upward { size - 1 - step } else { step };
            for dx in 0..2 {
                let x = (right - dx) as usize;
                if !is_fn[y * size + x] {
                    let dark = if bit_idx < total_bits {
                        ((codewords[bit_idx >> 3] >> (7 - (bit_idx & 7))) & 1) != 0
                    } else {
                        false
                    };
                    mods[y * size + x] = dark;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

fn apply_mask(size: usize, mask: u16, mods: &mut [bool], is_fn: &[bool]) {
    for y in 0..size {
        for x in 0..size {
            if is_fn[y * size + x] {
                continue;
            }
            let invert = match mask {
                0 => ((y + x) & 1) == 0,
                1 => (y & 1) == 0,
                2 => x.is_multiple_of(3),
                3 => (y + x).is_multiple_of(3),
                4 => (((y / 2) + (x / 3)) & 1) == 0,
                5 => ((y * x) & 1) + ((y * x) % 3) == 0,
                6 => ((((y * x) & 1) + ((y * x) % 3)) & 1) == 0,
                7 => ((((y + x) & 1) + ((y * x) % 3)) & 1) == 0,
                _ => false,
            };
            if invert {
                mods[y * size + x] = !mods[y * size + x];
            }
        }
    }
}

fn format_info_bits_l(mask: u16) -> u16 {
    // ECC Level L indicator = 0b01
    let data = (0b01u16 << 3) | (mask & 0b111);
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if (rem & (1 << (i + 10))) != 0 {
            rem ^= 0x537 << i;
        }
    }
    ((data << 10) | rem) ^ 0x5412
}

fn draw_format_bits(size: usize, mask: u16, mods: &mut [bool]) {
    let bits = format_info_bits_l(mask);
    let bit = |i: usize| -> bool { ((bits >> i) & 1) != 0 };

    // Copy 1: around top-left finder
    for i in 0..=5 {
        mods[i * size + 8] = bit(i);
    }
    mods[7 * size + 8] = bit(6);
    mods[8 * size + 8] = bit(7);
    mods[8 * size + 7] = bit(8);
    for i in 9..=14 {
        mods[8 * size + (14 - i)] = bit(i);
    }

    // Copy 2: top-right and bottom-left
    for i in 0..=7 {
        mods[8 * size + (size - 1 - i)] = bit(i);
    }
    for i in 8..=14 {
        mods[(size - 15 + i) * size + 8] = bit(i);
    }
    mods[(size - 8) * size + 8] = true;
}

fn compute_penalty(size: usize, mods: &[bool]) -> u32 {
    let mut score = 0u32;

    // Rule 1: runs of >= 5 same-colored modules in rows and columns.
    for y in 0..size {
        let mut run_color = mods[y * size];
        let mut run_len = 1u32;
        for x in 1..size {
            if mods[y * size + x] == run_color {
                run_len += 1;
                if run_len == 5 {
                    score += 3;
                } else if run_len > 5 {
                    score += 1;
                }
            } else {
                run_color = mods[y * size + x];
                run_len = 1;
            }
        }
    }
    for x in 0..size {
        let mut run_color = mods[x];
        let mut run_len = 1u32;
        for y in 1..size {
            if mods[y * size + x] == run_color {
                run_len += 1;
                if run_len == 5 {
                    score += 3;
                } else if run_len > 5 {
                    score += 1;
                }
            } else {
                run_color = mods[y * size + x];
                run_len = 1;
            }
        }
    }

    // Rule 2: 2x2 blocks of same color.
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let c = mods[y * size + x];
            if c == mods[y * size + x + 1]
                && c == mods[(y + 1) * size + x]
                && c == mods[(y + 1) * size + x + 1]
            {
                score += 3;
            }
        }
    }

    // Rule 3: finder-like 1:1:3:1:1 patterns with 4 light modules on either side.
    const P1: [bool; 11] = [
        true, false, true, true, true, false, true, false, false, false, false,
    ];
    const P2: [bool; 11] = [
        false, false, false, false, true, false, true, true, true, false, true,
    ];
    for y in 0..size {
        for x in 0..=size.saturating_sub(11) {
            let row_slice = &mods[y * size + x..y * size + x + 11];
            if row_slice == P1 || row_slice == P2 {
                score += 40;
            }
        }
    }
    for x in 0..size {
        for y in 0..=size.saturating_sub(11) {
            let mut m1 = true;
            let mut m2 = true;
            for k in 0..11 {
                let v = mods[(y + k) * size + x];
                if v != P1[k] {
                    m1 = false;
                }
                if v != P2[k] {
                    m2 = false;
                }
            }
            if m1 || m2 {
                score += 40;
            }
        }
    }

    // Rule 4: dark/light balance.
    let dark = mods.iter().filter(|&&b| b).count();
    let total = size * size;
    let k = ((dark * 20).abs_diff(total * 10)) / total;
    score += (k as u32) * 10;

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bits_match_iso_18004_table() {
        // ISO/IEC 18004 Table C.1: Level L (01), Mask 0..7
        assert_eq!(format_info_bits_l(0), 0x77C4);
        assert_eq!(format_info_bits_l(1), 0x72F3);
        assert_eq!(format_info_bits_l(2), 0x7DAA);
        assert_eq!(format_info_bits_l(3), 0x789D);
        assert_eq!(format_info_bits_l(4), 0x662F);
        assert_eq!(format_info_bits_l(5), 0x6318);
        assert_eq!(format_info_bits_l(6), 0x6C41);
        assert_eq!(format_info_bits_l(7), 0x6976);
    }

    #[test]
    fn reed_solomon_matches_iso_18004_version1_m_example() {
        // Known RS check: generator of degree 7 for V1-L produces valid zero-syndrome codewords.
        let data = build_byte_mode_codewords(b"192.168.1.10:5026", 1, 19);
        assert_eq!(data.len(), 19);
        let gen = rs_generator_poly(7);
        let ecc = rs_compute_remainder(&data, &gen);
        assert_eq!(ecc.len(), 7);
        // Verify codeword polynomial evaluates to 0 at alpha^0 .. alpha^6.
        let mut full = data;
        full.extend_from_slice(&ecc);
        let mut root = 1u8;
        for _ in 0..7 {
            let mut eval = 0u8;
            for &c in &full {
                eval = gf_mul(eval, root) ^ c;
            }
            assert_eq!(eval, 0);
            root = gf_mul(root, 2);
        }
    }

    #[test]
    fn encodes_urls_into_valid_matrix_terminal_and_svg() {
        let qr = QrCode::encode("http://192.0.2.100:8787/view").unwrap();
        // 28 bytes fits in Version 2-L (25x25, capacity 32 bytes)
        assert_eq!(qr.size(), 25);
        // Check top-left 7x7 finder corners and center
        assert!(qr.get(0, 0));
        assert!(qr.get(6, 0));
        assert!(qr.get(3, 3));
        assert!(!qr.get(1, 1));
        // Dark module at (8, size - 8)
        assert!(qr.get(8, 17));

        let term = qr.to_terminal_string();
        assert!(term.contains("\x1b[47;30m"));
        assert!(term.contains("\x1b[0m"));

        let svg = qr.to_svg();
        assert!(svg.starts_with("<svg "));
        assert!(svg.contains("viewBox=\"0 0 33 33\""));
        assert!(svg.ends_with("</svg>"));
    }

    #[test]
    fn supports_version_6_and_version_10_interleaving() {
        let long_url = format!("http://192.168.100.200:8787/view?note={}", "a".repeat(80));
        let qr = QrCode::encode(&long_url).unwrap();
        assert_eq!(qr.size(), 41);

        // ISO/IEC 18004 Table D.1 check: Version 7 = 0x07C94
        assert_eq!(version_info_bits(7), 0x07C94);

        let v10_url = format!("http://192.168.100.200:8787/view?token={}", "x".repeat(210));
        let qr10 = QrCode::encode(&v10_url).unwrap();
        assert_eq!(qr10.size(), 57);
    }
}
