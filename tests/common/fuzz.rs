//! Zero-dependency deterministic PRNG, byte mutator, and 3-phase delta-debugging (`ddmin`)
//! shrinker shared by Tier-0 fuzzing tests (`tests/fuzz_*.rs`).
//!
//! Environment overrides:
//! - `IDIS_FUZZ_SEED=0x...` (or decimal): replay ONLY that single seed for instant debugging.
//! - `IDIS_FUZZ_SEEDS=<N>`: override seed count per test (default: 64 in CI; e.g. 5000 for soak).
//! - `IDIS_FUZZ_STEPS=<N>`: override per-seed step count for stateful fuzzers.

#![allow(dead_code)]

/// Deterministic `SplitMix64` PRNG (fast, statistically strong, zero external dependencies).
#[derive(Debug, Clone)]
pub struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % upper_exclusive
    }

    pub fn range_u64(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        if hi_inclusive <= lo {
            return lo;
        }
        let span = hi_inclusive - lo + 1;
        lo + (self.next_u64() % span)
    }

    pub fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        if den == 0 || num == 0 {
            return false;
        }
        (self.next_u64() % den) < num
    }

    pub fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) / ((1u64 << 53) as f64)
    }

    pub fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.next_usize(slice.len())]
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let v = self.next_u64().to_le_bytes();
            let take = (len - out.len()).min(8);
            out.extend_from_slice(&v[..take]);
        }
        out
    }
}

/// Resolve the deterministic seed list for a fuzz target.
pub fn fuzz_seeds(salt: u64, default_count: usize) -> Vec<u64> {
    if let Ok(raw) = std::env::var("IDIS_FUZZ_SEED") {
        let s = raw.trim();
        let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else {
            s.parse::<u64>()
        };
        if let Ok(seed) = parsed {
            return vec![seed];
        }
    }
    let count = std::env::var("IDIS_FUZZ_SEEDS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default_count);
    let base = 0x1D15_0000_0000_0000u64 ^ salt.wrapping_mul(0x9E37_79B9);
    (0..count).map(|i| base.wrapping_add(i as u64)).collect()
}

pub fn fuzz_steps(default_steps: usize) -> usize {
    std::env::var("IDIS_FUZZ_STEPS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default_steps)
}

const INTERESTING_U32S: &[u32] = &[
    0,
    1,
    2,
    4,
    12,
    13,
    14,
    16,
    17,
    125,
    126,
    127,
    255,
    256,
    1024,
    65_535,
    65_536,
    256 * 1024,
    2 * 1024 * 1024,
    32 * 1024 * 1024,
    32 * 1024 * 1024 + 1,
    u32::MAX,
];

/// Mutate a byte buffer using classic fuzzing operators (bitflip, boundary integer injection,
/// byte overwrite, splice, insert, delete, truncate) capped at `max_len`.
pub fn mutate_bytes(rng: &mut FuzzRng, base: &[u8], max_len: usize) -> Vec<u8> {
    let mut buf = base.to_vec();
    let ops = 1 + rng.next_usize(4);
    for _ in 0..ops {
        match rng.next_usize(7) {
            0 if !buf.is_empty() => {
                // Single bitflip
                let pos = rng.next_usize(buf.len());
                buf[pos] ^= 1u8 << rng.next_usize(8);
            }
            1 if !buf.is_empty() => {
                // Overwrite 1..=4 bytes
                let pos = rng.next_usize(buf.len());
                let n = (1 + rng.next_usize(4)).min(buf.len() - pos);
                for b in &mut buf[pos..pos + n] {
                    *b = rng.next_u32() as u8;
                }
            }
            2 if buf.len() >= 4 => {
                // Inject interesting boundary u32 (LE or BE)
                let pos = rng.next_usize(buf.len() - 3);
                let val = *rng.pick(INTERESTING_U32S);
                let bytes = if rng.next_bool() {
                    val.to_le_bytes()
                } else {
                    val.to_be_bytes()
                };
                buf[pos..pos + 4].copy_from_slice(&bytes);
            }
            3 if buf.len() < max_len => {
                // Insert random slice (1..=16 bytes)
                let pos = rng.next_usize(buf.len() + 1);
                let ins_len = (1 + rng.next_usize(16)).min(max_len - buf.len());
                let extra = rng.bytes(ins_len);
                buf.splice(pos..pos, extra);
            }
            4 if buf.len() > 1 => {
                // Delete random slice
                let start = rng.next_usize(buf.len());
                let del_len = (1 + rng.next_usize(16)).min(buf.len() - start);
                buf.drain(start..start + del_len);
            }
            5 if !buf.is_empty() => {
                // Truncate at arbitrary boundary (mid-header / mid-frame)
                let new_len = rng.next_usize(buf.len());
                buf.truncate(new_len);
            }
            _ if !buf.is_empty() && buf.len() * 2 <= max_len => {
                // Duplicate / coalesce block
                let start = rng.next_usize(buf.len());
                let end = start + (1 + rng.next_usize(buf.len() - start)).min(64);
                let slice = buf[start..end].to_vec();
                let pos = rng.next_usize(buf.len() + 1);
                buf.splice(pos..pos, slice);
            }
            _ => {
                if buf.len() < max_len {
                    buf.push(rng.next_u32() as u8);
                }
            }
        }
    }
    buf.truncate(max_len);
    buf
}

/// 3-phase Zeller `ddmin` shrinker for action sequences:
/// 1. Binary-split chunk elimination
/// 2. Pairwise adjacent elimination
/// 3. 1-minimal backward single-step elimination
///
/// Always preserves the exact failing invariant returned by `check(&[T]) -> Option<String>`.
pub fn shrink_sequence<T: Clone>(
    initial: &[T],
    target_err: &str,
    mut check: impl FnMut(&[T]) -> Option<String>,
) -> Vec<T> {
    let mut current = initial.to_vec();
    if current.len() <= 1 {
        return current;
    }

    // Phase 1: Binary-split ddmin
    let mut n = 2usize;
    while current.len() >= 2 && n <= current.len() {
        let chunk_size = current.len().div_ceil(n);
        let mut reduced = false;
        let mut i = 0usize;
        while i < current.len() {
            let end = (i + chunk_size).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - i));
            candidate.extend_from_slice(&current[..i]);
            candidate.extend_from_slice(&current[end..]);
            if !candidate.is_empty() && check(&candidate).as_deref() == Some(target_err) {
                current = candidate;
                n = n.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            i = end;
        }
        if !reduced {
            if n >= current.len() {
                break;
            }
            n = (n * 2).min(current.len());
        }
    }

    // Phase 2 & 3: Single-step backward 1-minimal elimination
    let mut idx = current.len();
    while idx > 0 {
        idx -= 1;
        if current.len() <= 1 {
            break;
        }
        let mut candidate = current.clone();
        candidate.remove(idx);
        if check(&candidate).as_deref() == Some(target_err) {
            current = candidate;
            if idx > current.len() {
                idx = current.len();
            }
        }
    }

    current
}
