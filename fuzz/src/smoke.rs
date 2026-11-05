//! Deterministic bounded smoke runner for the fuzz entry points.
//!
//! `cargo fuzz` needs nightly; this binary needs only the pinned stable
//! toolchain. It feeds a fixed, generated set of inputs (valid-ish headers,
//! truncations, bit flips, random bytes) through the same calls the libFuzzer
//! targets make, with the same size ceilings. A panic is a failure; an `Err`
//! is expected and ignored.
//!
//! ```text
//! cargo run --manifest-path fuzz/Cargo.toml --bin smoke
//! ```
//!
//! This is a regression gate, not a substitute for fuzzing: coverage-guided
//! mutation finds paths this generator does not.

use std::process::ExitCode;

const MAX_PE: usize = 64 * 1024;
const MAX_METADATA: usize = 2 * 1024 * 1024;

/// Tiny deterministic PRNG (xorshift64*), so the smoke corpus is identical on
/// every run and platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

fn main() -> ExitCode {
    let mut rng = Rng(0x5EED_1234_ABCD_9876);
    let mut iterations = 0usize;

    // --- PE-shaped inputs ---------------------------------------------------
    let mut seeds: Vec<Vec<u8>> = vec![
        crackproof_pe(false, false),
        crackproof_pe(true, false),
        crackproof_pe(false, true),
        crackproof_pe(true, true),
        plain_pe(),
        clean_metadata(),
        obfuscated_metadata(),
    ];
    for seed in &seeds {
        iterations += mutations(seed, &mut rng);
    }
    // Pure random blobs of a few sizes.
    for length in [0usize, 1, 4, 64, 4128, 8192, MAX_PE] {
        let data: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        pe_calls(&data);
        iterations += 1;
    }
    // Truncations and bit flips of each seed.
    for seed in seeds.clone() {
        for cut in [0, 1, 2, 3, 4, 8, 16, 4096, seed.len() / 2] {
            let data = &seed[..cut.min(seed.len())];
            pe_calls(data);
            metadata_calls(data);
            iterations += 1;
        }
    }
    seeds.clear();

    // --- ELF shape ----------------------------------------------------------
    let elf = minimal_elf();
    for cut in [0, 4, 6, 16, 64, elf.len()] {
        elf_calls(&elf[..cut.min(elf.len())]);
        iterations += 1;
    }
    let mut mutated = elf.clone();
    for _ in 0..256 {
        let index = rng.below(mutated.len());
        mutated[index] ^= 1 << (rng.below(8) as u8);
    }
    elf_calls(&mutated);
    iterations += 1;

    println!("fuzz smoke: {iterations} iteration(s), no panic");
    ExitCode::SUCCESS
}

fn mutations(seed: &[u8], rng: &mut Rng) -> usize {
    let mut count = 0;
    pe_calls(seed);
    metadata_calls(seed);
    count += 1;
    for _ in 0..64 {
        let mut data = seed.to_vec();
        let flips = 1 + rng.below(8);
        for _ in 0..flips {
            let index = rng.below(data.len());
            data[index] ^= 1 << (rng.below(8) as u8);
        }
        let truncate = rng.below(data.len() + 1);
        data.truncate(truncate);
        pe_calls(&data);
        metadata_calls(&data);
        count += 1;
    }
    count
}

fn pe_calls(data: &[u8]) {
    let data = &data[..data.len().min(MAX_PE)];
    let _ = senbei_engine::detect(data);
    let _ = senbei_engine::check_integrity(data);
    if let Ok(headers) = senbei_pe::parse(data) {
        let _ = senbei_pe::sections(data, headers);
        let _ = senbei_pe::characteristics(data, headers);
        for index in 0..16u16 {
            let _ = senbei_pe::data_directory(data, headers, index);
        }
        let _ = senbei_pe::rva_to_offset(data, headers, headers.entry_rva);
        let _ = senbei_pe::rva_range(data, headers, headers.entry_rva, 0x10);
        let _ = senbei_pe::rva_range(data, headers, u32::MAX, 4);
    }
}

fn metadata_calls(data: &[u8]) {
    let data = &data[..data.len().min(MAX_METADATA)];
    if !senbei_metadata::is_metadata(data) {
        return;
    }
    let _ = senbei_metadata::deobfuscate(data);
    let _ = senbei_metadata::android::discover_method_token_seeds(data);
    if let Some((&selector, body)) = data.split_first() {
        let _ = senbei_metadata::android::restore_method_tokens(body, u32::from(selector));
    }
    let _ = senbei_metadata::android::restore_method_indices_v24_1(data, data);
    let _ = senbei_metadata::android::extract_embedded_metadata(data);
}

fn elf_calls(data: &[u8]) {
    if !senbei_elf::is_aarch64_prefix(data) {
        return;
    }
    let _ = senbei_elf::is_aarch64(data);
    let _ = senbei_elf::load_file_end(data);
    if let Ok(layout) = senbei_elf::ElfLayout::parse(data, false) {
        let _ = layout.load_end();
        let _ = layout.section_names(data);
    }
}

fn crackproof_pe(dll: bool, managed: bool) -> Vec<u8> {
    const KONN: u32 = 0x4E4E_4F4B;
    const PE: usize = 0x80;
    let mut data = vec![0u8; 4096 + 32];
    data[..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&(PE as u32).to_le_bytes());
    data[PE..PE + 4].copy_from_slice(b"PE\0\0");
    let chars: u16 = if dll { 0x2000 } else { 0 };
    data[PE + 22..PE + 24].copy_from_slice(&chars.to_le_bytes());
    data[PE + 20..PE + 22].copy_from_slice(&0xF0u16.to_le_bytes());
    data[PE + 24..PE + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
    let directories = PE + 24 + 112;
    if managed {
        data[directories + 14 * 8..directories + 14 * 8 + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        data[directories + 14 * 8 + 4..directories + 14 * 8 + 8]
            .copy_from_slice(&0x48u32.to_le_bytes());
    }
    data[4096..4100].copy_from_slice(&0u32.to_le_bytes());
    data[4100..4104].copy_from_slice(&KONN.to_le_bytes());
    data
}

fn plain_pe() -> Vec<u8> {
    let mut data = crackproof_pe(false, false);
    data[4100..4104].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    data
}

const METADATA_MAGIC: u32 = 0xFAB1_1BAF;

fn clean_metadata() -> Vec<u8> {
    metadata(&[
        0x0600_0001,
        0x0600_0002,
        0x0600_0001,
        0x0600_0002,
        0x0600_0003,
    ])
}

fn obfuscated_metadata() -> Vec<u8> {
    metadata(&[
        0x0600_D49F,
        0x0600_FFFF,
        0x0600_1234,
        0x0600_ABCD,
        0x0600_5555,
    ])
}

fn metadata(tokens: &[u32; 5]) -> Vec<u8> {
    const HDR_METHODS: usize = 0x30;
    const HDR_TYPES: usize = 0xA0;
    const HDR_IMAGES: usize = 0xA8;
    let images = 0x100usize;
    let types = images + 2 * 0x28;
    let methods = types + 2 * 0x58;
    let mut data = vec![0u8; methods + tokens.len() * 0x24];
    let put32 = |data: &mut [u8], offset: usize, value: u32| {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
    };
    let put16 = |data: &mut [u8], offset: usize, value: u16| {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes())
    };
    put32(&mut data, 0, METADATA_MAGIC);
    put32(&mut data, 4, 31);
    put32(&mut data, HDR_METHODS, methods as u32);
    put32(&mut data, HDR_METHODS + 4, (tokens.len() * 0x24) as u32);
    put32(&mut data, HDR_TYPES, types as u32);
    put32(&mut data, HDR_TYPES + 4, (2 * 0x58) as u32);
    put32(&mut data, HDR_IMAGES, images as u32);
    put32(&mut data, HDR_IMAGES + 4, (2 * 0x28) as u32);
    put32(&mut data, images + 0x08, 0);
    put32(&mut data, images + 0x0C, 1);
    put32(&mut data, images + 0x28 + 0x08, 1);
    put32(&mut data, images + 0x28 + 0x0C, 1);
    put32(&mut data, types + 0x24, 0);
    put16(&mut data, types + 0x40, 2);
    put32(&mut data, types + 0x58 + 0x24, 2);
    put16(&mut data, types + 0x58 + 0x40, 3);
    for (index, token) in tokens.iter().enumerate() {
        put32(&mut data, methods + index * 0x24 + 0x18, *token);
    }
    data
}

fn minimal_elf() -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // ELF64
    data[5] = 1; // little-endian
    data[6] = 1;
    data[0x12..0x14].copy_from_slice(&0xB7u16.to_le_bytes()); // AArch64
    data[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    data[0x18..0x20].copy_from_slice(&0x1000u64.to_le_bytes());
    data[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    data[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
    data[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
    data[0x38..0x3A].copy_from_slice(&0u16.to_le_bytes());
    data[0x3A..0x3C].copy_from_slice(&0x40u16.to_le_bytes());
    data[0x3C..0x3E].copy_from_slice(&0u16.to_le_bytes());
    data
}
