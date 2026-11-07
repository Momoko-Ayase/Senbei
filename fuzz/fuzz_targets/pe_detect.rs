#![no_main]

//! CrackProof PE detection over bounded, attacker-shaped bytes.
//!
//! Ceilings: input is capped by the harness (`-max_len`, see run.sh) and the
//! detector itself reads only fixed header offsets. This target asserts the
//! detector never panics — the folder scanner calls it on untrusted prefixes.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    let _ = senbei_engine::detect(data);
});
