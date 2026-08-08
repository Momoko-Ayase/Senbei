// Bytecode interpreter for the custom-decryptor stages. Those stages are tiny
// instruction programs embedded in the decrypted buffer; we compile each
// program down to a Vec<Op> and interpret it.

#[derive(Clone, Copy)]
pub enum Op {
    Add(u8),
    Sub(u8),
    Xor(u8),
    Rol(u32),
    Ror(u32),
    Inc,
    Dec,
}

pub fn apply(ops: &[Op], mut x: u8) -> u8 {
    for &op in ops {
        x = match op {
            Op::Add(n) => x.wrapping_add(n),
            Op::Sub(n) => x.wrapping_sub(n),
            Op::Xor(n) => x ^ n,
            Op::Rol(n) => x.rotate_left(n & 7),
            Op::Ror(n) => x.rotate_right(n & 7),
            Op::Inc => x.wrapping_add(1),
            Op::Dec => x.wrapping_sub(1),
        };
    }
    x
}

/// A precomputed 256-entry byte→byte translation table for a fixed op list.
///
/// `apply` is a pure function of a single byte, but the hot decrypt paths run it
/// over multi-megabyte regions. Building the full table once and translating
/// each byte with a single lookup turns an O(region × ops) walk into O(region) —
/// a large constant-factor win on those paths.
pub struct OpsLut {
    t: [u8; 256],
}

impl OpsLut {
    pub fn new(ops: &[Op]) -> Self {
        let mut t = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            t[i] = apply(ops, i as u8);
            i += 1;
        }
        Self { t }
    }

    /// Translate `d[off .. off + n]` in place through the table.
    #[inline]
    pub fn map_region(&self, d: &mut [u8], off: usize, n: usize) {
        for b in &mut d[off..off + n] {
            *b = self.t[*b as usize];
        }
    }
}

pub fn generate(data: &[u8], offset: u32) -> Option<Vec<Op>> {
    // Bounds-checked cursor: a corrupt `data_offset` (bad decrypt_data6 / the
    // alignment fallback) must yield `None`, not an out-of-bounds panic — the
    // panic path would surface as a misleading `UnpackError::Corrupt` instead
    // of the precise `BytecodeGenFailed`, and any future caller without a
    // `catch_unwind` wrapper would abort outright.
    let mut pos = offset as usize;
    let mut next = move || {
        let b = data.get(pos).copied()?;
        pos += 1;
        Some(b)
    };
    let mut ops = Vec::new();
    loop {
        match next()? {
            4 => ops.push(Op::Add(next()?)),
            44 => ops.push(Op::Sub(next()?)),
            52 => ops.push(Op::Xor(next()?)),
            144 => {} // nop
            192 => {
                let mb = next()?;
                let rm = mb & 7;
                let reg = (mb >> 3) & 7;
                let mod_ = (mb >> 6) & 3;
                if mod_ != 3 || rm != 0 {
                    return None;
                }
                let imm = next()? as u32;
                match reg {
                    0 => ops.push(Op::Rol(imm)),
                    1 => ops.push(Op::Ror(imm)),
                    _ => {
                        return None;
                    }
                }
            }
            254 => {
                let mb = next()?;
                let rm = mb & 7;
                let reg = (mb >> 3) & 7;
                let mod_ = (mb >> 6) & 3;
                if mod_ != 3 || rm != 0 {
                    return None;
                }
                match reg {
                    0 => ops.push(Op::Inc),
                    1 => ops.push(Op::Dec),
                    _ => {
                        return None;
                    }
                }
            }
            195 => return Some(ops),
            _ => {
                return None;
            }
        }
    }
}
