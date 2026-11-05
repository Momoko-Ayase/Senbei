#![no_main]

//! Static PE integrity check over arbitrary images.
//!
//! The checker is documented never to panic on any input; this target enforces
//! that. Input is capped so a crafted `SizeOfImage` cannot turn one iteration
//! into a multi-gigabyte allocation.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 512 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    let report = senbei_engine::check_integrity(data);
    // Keep the report observable so the optimizer cannot elide the call.
    std::hint::black_box(report.issues.len());
    std::hint::black_box(report.findings.len());
});
