//! Validation-driven selection for per-page text transforms.

use super::discovery::trial_decrypt5_u32;

/// PE32 `.text` dd8 key-formula selection with a skip decision. The packer keys
/// the per-page XOR either with `page+1` or `0x8000*(page+1)`; the formula is
/// not recorded. Replays the dd8 page pass on a scratch copy of sample pages
/// (25/50/75% of `.text`) under each formula and counts how many positions
/// decode to `0xCC` (int3 padding).
///
/// Returns `Some(true)` for the `0x8000*(page+1)` formula, `Some(false)` for
/// `page+1`, or `None` when `.text` must NOT be dd8-decrypted at all. The packer
/// dd8-encrypts `.text` on EXEs (so unpacking must replay it) but leaves a native
/// DLL's `.text` plaintext; replaying dd8 there scrambles ~1 byte per 16-byte
/// block. The decision: dd8 only *restores* int3 padding when `.text` was
/// genuinely encrypted, so apply it only when the chosen formula's whole-page
/// 0xCC count rises *clearly* above the no-dd8 baseline; otherwise skip.
///
/// "Clearly" matters: dd8 XORs 255 positions per page with pseudo-random bytes,
/// so on an already-plaintext `.text` it manufactures ~1 spurious `0xCC` per
/// sampled page for free (255/256 expected). A bare `best > baseline` test is
/// therefore biased towards *applying* dd8 on exactly the inputs that must skip
/// it — and a wrongly-applied dd8 is silent: it scrambles ~1 byte per 16 with no
/// error and nothing downstream (not even `integrity::check`, which only reads
/// 16 bytes at the entry point) notices. The [`MIN_DD8_NET_GAIN`] floor below is
/// the PE32 counterpart of the margin+floor `select_dd8_shift` already applies
/// on PE32+ for the same failure mode.
pub fn select_dd8_formula_pe32(data: &[u8], text_off: u32, text_size: u32) -> Option<bool> {
    let num_pages_total = text_size / 0x1000;
    let mut sample_pages: Vec<u32> = Vec::new();
    for frac in [0.25f64, 0.5, 0.75] {
        let pg = (num_pages_total as f64 * frac) as u32;
        if pg > 0 && pg < num_pages_total {
            sample_pages.push(pg);
        }
    }
    if sample_pages.is_empty() && num_pages_total > 1 {
        sample_pages.push(num_pages_total / 2);
    }
    let score = |big: bool| -> i64 {
        let mut total = 0i64;
        for &sp in &sample_pages {
            let pg_off = (text_off + sp * 0x1000) as usize;
            if pg_off + 0x1000 > data.len() {
                continue;
            }
            let mut buf = [0u8; 0x1000];
            buf.copy_from_slice(&data[pg_off..pg_off + 0x1000]);
            let pk = if big {
                0x8000u32.wrapping_mul(sp.wrapping_add(1))
            } else {
                sp.wrapping_add(1)
            };
            let mut k = pk;
            let rk = k.rotate_right(15);
            k = rk;
            for bi in 1..256u32 {
                let rk = k.rotate_right(15);
                let ri = rk.wrapping_add(bi);
                k = ri.wrapping_add(bi);
                let tidx = (bi.wrapping_mul(16).wrapping_add(ri & 0xF)) as usize;
                if tidx < buf.len() {
                    buf[tidx] ^= k as u8;
                }
            }
            total += buf.iter().filter(|&&b| b == 0xCC).count() as i64;
        }
        total
    };
    let s_small = score(false);
    let s_big = score(true);
    // Baseline: whole-page 0xCC over the same sample pages with NO dd8. dd8 only
    // rewrites 255 bytes per page, so comparing the chosen formula's whole-page
    // 0xCC against this baseline reveals whether dd8 *restores* int3 padding
    // (count rises -> .text was packer-encrypted, apply) or merely scrambles
    // already-plaintext code (count falls -> native-DLL .text left intact, skip).
    let mut baseline: i64 = 0;
    for &sp in &sample_pages {
        let pg_off = (text_off + sp * 0x1000) as usize;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        baseline += data[pg_off..pg_off + 0x1000]
            .iter()
            .filter(|&&b| b == 0xCC)
            .count() as i64;
    }
    let big = s_big > s_small;
    let best = s_small.max(s_big);
    // Minimum net 0xCC gain over the baseline before dd8 is applied. Noise on an
    // already-plaintext `.text` is ~1 manufactured 0xCC per sampled page (3 pages
    // -> ~3); every corpus build that genuinely needs dd8 gains +154 or more
    // (observed +154 and +312), and the one native DLL that must skip scores -18.
    // A floor of 32 sits ~10x above the noise and ~5x below the smallest true
    // positive, so it changes no existing decision.
    const MIN_DD8_NET_GAIN: i64 = 32;
    let apply = best.saturating_sub(baseline) >= MIN_DD8_NET_GAIN;
    if std::env::var("SEL_DIAG").is_ok() {
        eprintln!(
            "SEL pe32 dd8 s_small={} s_big={} baseline={} gain={} big={} apply={}",
            s_small,
            s_big,
            baseline,
            best - baseline,
            big,
            apply
        );
    }
    // When no interior pages could be sampled (tiny .text) we cannot measure the
    // effect; preserve the historical behavior of applying dd8.
    if sample_pages.is_empty() || apply {
        Some(big)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// dd8 page-XOR shift selection.
//
// The packer scrambles ~1 byte per 16-byte block of .text via decrypt_data8,
// keyed by `page_idx << shift` (absolute page index = text_va >> 12). Observed
// shifts are 0 and 15. The shift is NOT stored in any header/config field, so
// the decision must be validated against the resulting .text content.
//
// A recognised CRT entry stub is the strongest oracle: decode skip/0/15 and
// require both of its direct rel32 branches to land in executable .text. This
// includes the call/jump displacement bytes themselves; an older entry oracle
// wildcarded those bytes and could accept a stub whose opcodes looked right but
// whose branch targets were outside the image.
//
// Other entry shapes fall back to padding statistics: replay each shift across
// sample pages and count positions restored to the MSVC int3 padding byte. A
// clear gain selects the shift; otherwise .text is treated as already plain.
// ---------------------------------------------------------------------------
pub fn select_dd8_shift(data: &[u8], text_va: u32, text_size: u32, info3: u32) -> u32 {
    if let Some((shift, scores)) = select_dd8_by_entry_stub(data, text_va, text_size, info3) {
        if std::env::var("SEL_DIAG").is_ok() {
            eprintln!(
                "SEL dd8 entry best_shift={} none={} s0={} s15={}",
                shift, scores[0], scores[1], scores[2]
            );
        }
        return shift;
    }
    if text_size < 0x1000 {
        return 0;
    }
    let text_off = text_va as usize;
    let num_pages_total = text_size >> 12;

    // Sample pages at 25/50/75% of .text, falling back to the midpoint for tiny
    // sections.
    let mut sample_pages: Vec<u32> = Vec::new();
    for frac in [0.25f64, 0.5, 0.75] {
        let pg = (num_pages_total as f64 * frac) as u32;
        if pg > 0 && pg < num_pages_total {
            sample_pages.push(pg);
        }
    }
    if sample_pages.is_empty() && num_pages_total > 1 {
        sample_pages.push(num_pages_total / 2);
    }
    if sample_pages.is_empty() {
        return 0;
    }

    let none_hits = score_dd8_baseline(data, text_off, &sample_pages);
    let s0 = score_dd8_shift(data, text_off, text_va, &sample_pages, 0);
    let s15 = score_dd8_shift(data, text_off, text_va, &sample_pages, 15);
    let mut best_score = none_hits;
    let mut best_shift = 99u32; // 99 == skip dd8
    for (shift, hits) in [(0u32, s0), (15u32, s15)] {
        if hits > best_score {
            best_score = hits;
            best_shift = shift;
        }
    }
    // Require a clear 2x margin over the already-plaintext baseline AND an
    // absolute floor. The 2x test alone
    // trips on noise when the counts are tiny: an external-companion DLL whose
    // .text is already plaintext scores s15=4 vs none=1 — a spurious 4x — and
    // gets dd8 wrongly applied, corrupting ~1 byte per 16. Across the whole
    // golden corpus every build that genuinely needs dd8 scores >= 10 (lowest
    // observed scores at 10-12; up to 107), so a floor of 8 rejects the noise
    // while keeping every golden's shift selection unchanged.
    const MIN_DD8_HITS: u32 = 8;
    if best_shift != 99 && (best_score < none_hits * 2 || best_score < MIN_DD8_HITS) {
        best_shift = 99;
    }
    if std::env::var("SEL_DIAG").is_ok() {
        eprintln!(
            "SEL dd8 best_shift={} s0={} s15={} none_hits={} samples={:?}",
            best_shift, s0, s15, none_hits, sample_pages
        );
    }
    best_shift
}

/// Select DD8 from the common CRT entry stub when its direct call and jump
/// provide a stronger oracle than sparse padding statistics. The candidate is
/// accepted only when it is the sole one whose two branch targets stay inside
/// `.text`; unrecognised entry code falls through to the padding selector.
fn select_dd8_by_entry_stub(
    data: &[u8],
    text_va: u32,
    text_size: u32,
    info3: u32,
) -> Option<(u32, [u8; 3])> {
    for entry in entry_candidates(data, text_va, text_size, info3) {
        let [Some(none), Some(s0), Some(s15)] = [None, Some(0), Some(15)]
            .map(|shift| entry_stub_branch_score(data, text_va, text_size, entry, shift))
        else {
            continue;
        };
        let scores = [none, s0, s15];
        let best = scores.iter().copied().max()?;
        if best == 2 && scores.iter().filter(|&&score| score == best).count() == 1 {
            let index = scores.iter().position(|&score| score == best)?;
            return Some(([99, 0, 15][index], scores));
        }
    }
    None
}

fn entry_candidates(data: &[u8], text_va: u32, text_size: u32, info3: u32) -> Vec<u32> {
    let text_end = text_va.saturating_add(text_size);
    let mut entries = Vec::with_capacity(3);
    if let Some(pe) = read_u32(data, 0x3C)
        && let Some(entry) = pe.checked_add(40).and_then(|offset| read_u32(data, offset))
        && (text_va..text_end).contains(&entry)
    {
        entries.push(entry);
    }
    for metadata_off in [32u32, 64] {
        let Some(end) = info3
            .checked_add(metadata_off)
            .and_then(|offset| offset.checked_add(8))
        else {
            continue;
        };
        if end as usize > data.len() {
            continue;
        }
        let entry = trial_decrypt5_u32(data, info3 + metadata_off);
        let image_base = trial_decrypt5_u32(data, info3 + metadata_off + 4);
        if image_base == info3 && (text_va..text_end).contains(&entry) && !entries.contains(&entry)
        {
            entries.push(entry);
        }
    }
    entries
}

fn entry_stub_branch_score(
    data: &[u8],
    text_va: u32,
    text_size: u32,
    entry: u32,
    shift: Option<u32>,
) -> Option<u8> {
    let text_end = text_va.checked_add(text_size)?;
    if entry < text_va || entry.checked_add(18)? > text_end {
        return None;
    }

    let mut stub = [0u8; 18];
    for (offset, byte) in stub.iter_mut().enumerate() {
        *byte = dd8_candidate_byte(data, entry + offset as u32, shift)?;
    }
    if stub[0..3] != [0x48, 0x83, 0xEC]
        || stub[4] != 0xE8
        || stub[9..12] != [0x48, 0x83, 0xC4]
        || stub[12] != stub[3]
        || stub[13] != 0xE9
    {
        return None;
    }

    let call_rel = i32::from_le_bytes(stub[5..9].try_into().ok()?) as i64;
    let jump_rel = i32::from_le_bytes(stub[14..18].try_into().ok()?) as i64;
    let call_target = i64::from(entry) + 9 + call_rel;
    let jump_target = i64::from(entry) + 18 + jump_rel;
    let in_text = |target: i64| target >= i64::from(text_va) && target < i64::from(text_end);
    Some(u8::from(in_text(call_target)) + u8::from(in_text(jump_target)))
}

fn dd8_candidate_byte(data: &[u8], rva: u32, shift: Option<u32>) -> Option<u8> {
    let mut byte = *data.get(rva as usize)?;
    let Some(shift) = shift else {
        return Some(byte);
    };
    let page = rva >> 12;
    let block = (rva & 0xFFF) >> 4;
    let mut key = page << shift;
    for index in 0..=block {
        let mixed = key.rotate_right(15).wrapping_add(index);
        key = mixed.wrapping_add(index);
        if index != 0 {
            let target = (page << 12)
                .wrapping_add(index << 4)
                .wrapping_add(mixed & 0xF);
            if target == rva {
                byte ^= key as u8;
            }
        }
    }
    Some(byte)
}

fn read_u32(data: &[u8], offset: u32) -> Option<u32> {
    let start = offset as usize;
    let bytes = data.get(start..start.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

// Baseline: count int3 pads already present at the first byte of each 16-byte
// block, i.e. the positions dd8 would target if its in-block offset were 0.
fn score_dd8_baseline(data: &[u8], text_off: usize, sample_pages: &[u32]) -> u32 {
    let mut hits = 0u32;
    for &sp in sample_pages {
        let pg_off = text_off + (sp as usize) * 0x1000;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        for bi in 1..256usize {
            if data[pg_off + bi * 16] == 0xCC {
                hits += 1;
            }
        }
    }
    hits
}

// Replay decrypt_data8 on each sample page under `shift` and count how many of
// the 255 mutated positions decode to 0xCC.
fn score_dd8_shift(
    data: &[u8],
    text_off: usize,
    text_va: u32,
    sample_pages: &[u32],
    shift: u32,
) -> u32 {
    let abs_base = text_va >> 12;
    let mut hits = 0u32;
    for &sp in sample_pages {
        let pg_off = text_off + (sp as usize) * 0x1000;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        let abs_page = abs_base.wrapping_add(sp);
        let mut key = abs_page << shift;
        for bi in 0..256u32 {
            let mixed = key.rotate_right(15).wrapping_add(bi);
            key = mixed.wrapping_add(bi);
            if bi == 0 {
                continue;
            }
            let tidx = (bi.wrapping_mul(16).wrapping_add(mixed & 0xF)) as usize;
            if tidx < 0x1000 {
                let mutated = data[pg_off + tidx] ^ (key as u8);
                if mutated == 0xCC {
                    hits += 1;
                }
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_stub_fixture() -> Vec<u8> {
        let mut data = vec![0u8; 0x5000];
        data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x128..0x12C].copy_from_slice(&0x1264u32.to_le_bytes());
        data[0x1264..0x1276].copy_from_slice(&[
            0x48, 0x83, 0xEC, 0x28, 0xE8, 0x5B, 0x02, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9,
            0x7A, 0xFE, 0xFF, 0xFF,
        ]);
        data
    }

    fn apply_dd8_page(data: &mut [u8], page_rva: u32, shift: u32) {
        let mut key = (page_rva >> 12) << shift;
        for index in 0..256u32 {
            let mixed = key.rotate_right(15).wrapping_add(index);
            key = mixed.wrapping_add(index);
            if index == 0 {
                continue;
            }
            let target = page_rva.wrapping_add(index << 4).wrapping_add(mixed & 0xF) as usize;
            data[target] ^= key as u8;
        }
    }

    #[test]
    fn entry_stub_selects_plaintext_and_both_dd8_shifts() {
        let plain = entry_stub_fixture();
        assert_eq!(select_dd8_shift(&plain, 0x1000, 0x4000, 0), 99);

        for expected in [0u32, 15] {
            let mut encrypted = plain.clone();
            apply_dd8_page(&mut encrypted, 0x1000, expected);
            assert_eq!(select_dd8_shift(&encrypted, 0x1000, 0x4000, 0), expected);
        }
    }

    /// Seed the first `count` dd8-targeted positions of each sampled page with
    /// the byte that decodes to `0xCC` under the `page+1` formula — i.e. an
    /// encrypted `.text` whose plaintext is int3 padding. Positions whose key
    /// byte would make the *ciphertext* itself `0xCC` are skipped so the
    /// fixture contains no `0xCC` at all and every post-dd8 `0xCC` is a genuine
    /// gain over a zero baseline.
    fn seed_dd8_int3(data: &mut [u8], text_off: u32, pages: &[u32], count: u32) {
        for &sp in pages {
            let pg_off = (text_off + sp * 0x1000) as usize;
            let mut k = sp.wrapping_add(1);
            k = k.rotate_right(15);
            let mut planted = 0u32;
            for bi in 1..256u32 {
                let ri = k.rotate_right(15).wrapping_add(bi);
                k = ri.wrapping_add(bi);
                if planted >= count {
                    continue;
                }
                let ct = 0xCCu8 ^ (k as u8);
                if ct == 0xCC {
                    continue;
                }
                let tidx = (bi.wrapping_mul(16).wrapping_add(ri & 0xF)) as usize;
                data[pg_off + tidx] = ct;
                planted += 1;
            }
        }
    }

    /// Review regression: a near-plaintext `.text` must NOT be dd8-decrypted.
    /// dd8 XORs 255 positions per page with pseudo-random bytes, so it
    /// manufactures a few `0xCC` for free — under the old bare
    /// `best > baseline` test any positive gain was enough to "apply" dd8 and
    /// scramble ~1 byte per 16 of a native DLL's already-plaintext code,
    /// silently (nothing downstream, including the integrity check, notices).
    /// Here the gain is real but small; the floor must still reject it.
    #[test]
    fn pe32_dd8_skips_text_whose_gain_is_only_noise_sized() {
        let text_off: u32 = 0x1000;
        let text_size: u32 = 8 * 0x1000;
        let mut data = vec![0u8; (text_off + text_size) as usize];
        seed_dd8_int3(&mut data, text_off, &[2, 4, 6], 5);
        assert!(
            !data.contains(&0xCC),
            "fixture must have a zero 0xCC baseline"
        );
        assert_eq!(
            select_dd8_formula_pe32(&data, text_off, text_size),
            None,
            "a gain this small is indistinguishable from dd8's own noise"
        );
    }

    /// Control for the above: a `.text` whose dd8 pass restores a large amount
    /// of int3 padding clears the floor and is decrypted. Same fixture shape,
    /// only the amount of restored padding differs.
    #[test]
    fn pe32_dd8_applies_when_padding_is_restored() {
        let text_off: u32 = 0x1000;
        let text_size: u32 = 8 * 0x1000;
        let mut data = vec![0u8; (text_off + text_size) as usize];
        seed_dd8_int3(&mut data, text_off, &[2, 4, 6], 255);
        assert_eq!(
            select_dd8_formula_pe32(&data, text_off, text_size),
            Some(false),
            "encrypted .text must be decrypted with the page+1 formula"
        );
    }
}
