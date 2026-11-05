#![no_main]

//! PE header/RVA parser over arbitrary bytes.
//!
//! Exercises format parsing/mapping and the bounded research inspector,
//! including partially parsed inputs. A returned issue is fine; a panic is a bug.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    let limits = senbei_engine::windows::InspectionLimits {
        prefix_scratch_bytes: 64 * 1024,
        max_candidates: 16,
        max_issues: 16,
        ..Default::default()
    };
    let _ = senbei_engine::windows::inspect_research_with_limits(data, &limits);
    let Ok(headers) = senbei_pe::parse(data) else {
        return;
    };
    let _ = senbei_pe::sections(data, headers);
    let _ = senbei_pe::characteristics(data, headers);
    for index in 0..16u16 {
        let _ = senbei_pe::data_directory(data, headers, index);
    }
    let _ = senbei_pe::rva_to_offset(data, headers, headers.entry_rva);
    let _ = senbei_pe::rva_range(data, headers, headers.entry_rva, 0x10);
    let _ = senbei_pe::rva_range(data, headers, u32::MAX, 4);
});
