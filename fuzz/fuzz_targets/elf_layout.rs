#![no_main]

//! ELF64/AArch64 layout parsing and section-name resolution.
//!
//! Only structure is checked: no restoration, no filesystem. Input is capped
//! because the parser materializes program/section header vectors.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    if !senbei_elf::is_aarch64_prefix(data) {
        return;
    }
    let _ = senbei_elf::is_aarch64(data);
    let _ = senbei_elf::load_file_end(data);
    let Ok(layout) = senbei_elf::ElfLayout::parse(data, false) else {
        return;
    };
    let _ = layout.load_end();
    let _ = layout.file_load_end();
    let _ = layout.load_alignment();
    let _ = layout.section_names(data);
    let _ = layout.private_section();
});
