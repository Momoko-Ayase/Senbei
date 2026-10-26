use super::*;
use senbei_elf::LoadSegment;

fn fixture() -> (Vec<u8>, Vec<u8>, ElfLayout) {
    let mut module = vec![0; 0x2000];
    // Synthetic selector: check every primary, then call either all primary
    // or all fallback offsets. Bit 1 disables a record's instruction check;
    // null primaries are skipped. The entry reaches it through a direct call.
    let code: [u32; 41] = [
        0xd10043ff, // sub sp, sp, #16
        0xf90003fe, // str x30, [sp]
        0xf9400413, // ldr x19, [x0, #8]
        0xb0000014, // adrp x20, table page
        0x91200294, // add x20, x20, #0x800
        0xb9400295, // ldr w21, [x20] (count)
        0x91002294, // add x20, x20, #8 (records)
        0x52800016, // mov w22, #0 (fallback)
        0x52800017, // mov w23, #0 (index)
        0x6b1502ff, // cmp w23, w21
        0x540001e2, // b.hs checked
        0x8b171298, // add x24, x20, x23, lsl #4
        0xb9400300, // ldr w0, [x24]
        0x34000140, // cbz w0, check_next
        0xb9400f01, // ldr w1, [x24, #12]
        0x121f0021, // and w1, w1, #2
        0x350000e1, // cbnz w1, check_next
        0x8b000260, // add x0, x19, x0
        0xb9400000, // ldr w0, [x0]
        0xb9400b01, // ldr w1, [x24, #8]
        0x6b01001f, // cmp w0, w1
        0x54000040, // b.eq check_next
        0x52800036, // mov w22, #1
        0x110006f7, // add w23, w23, #1
        0x17fffff1, // b check
        0x52800017, // mov w23, #0
        0x6b1502ff, // cmp w23, w21
        0x54000142, // b.hs done
        0x8b171298, // add x24, x20, x23, lsl #4
        0xb9400300, // ldr w0, [x24]
        0x340000a0, // cbz w0, invoke_next
        0x34000056, // cbz w22, primary
        0xb9400700, // ldr w0, [x24, #4]
        0x8b000260, // add x0, x19, x0
        0xd63f0000, // blr x0
        0x110006f7, // add w23, w23, #1
        0x17fffff6, // b invoke
        0x52800020, // mov w0, #1
        0xf94003fe, // ldr x30, [sp]
        0x910043ff, // add sp, sp, #16
        0xd65f03c0, // ret
    ];
    put(&mut module, 0x40, 0x9400_0030);
    put(&mut module, 0x44, 0xd65f_03c0);
    for (index, instruction) in code.into_iter().enumerate() {
        put(&mut module, 0x100 + index * 4, instruction);
    }
    put(&mut module, 0x1800, 2);
    for (index, record) in [[0x4400, 0x4500, 0x1234, 0], [0x4200, 0x4520, 0x5678, 0]]
        .into_iter()
        .enumerate()
    {
        for (field, word) in record.into_iter().enumerate() {
            put(&mut module, 0x1808 + index * 16 + field * 4, word);
        }
    }
    let mut image = vec![0; 0x1000];
    put(&mut image, 0x400, 0x1234);
    put(&mut image, 0x200, 0x5678);
    let layout = ElfLayout {
        entrypoint: 0,
        program_header_offset: 0,
        program_header_size: 0x38,
        program_header_count: 1,
        program_headers: vec![LoadSegment {
            offset: 0,
            virtual_address: 0x4000,
            file_size: 0x1000,
            memory_size: 0x1000,
            flags: 5,
            alignment: 0x1000,
        }],
        section_headers: Vec::new(),
        section_name_index: 0,
        private_section_index: 0,
    };
    (module, image, layout)
}

fn put(data: &mut [u8], offset: usize, word: u32) {
    data[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}

#[test]
fn callback_order_comes_from_execution_even_after_module_relocation() {
    let (module, image, layout) = fixture();
    assert_eq!(
        callbacks(&module, 0x40, &image, &layout, 2).unwrap(),
        [0x4400, 0x4200]
    );
    let mut relocated = vec![0; 0x5000];
    relocated.extend_from_slice(&module);
    // Unreachable data and code cannot become another table candidate.
    relocated[..module.len()].copy_from_slice(&module);
    assert_eq!(
        callbacks(&relocated, 0x5040, &image, &layout, 2).unwrap(),
        [0x4400, 0x4200]
    );
}

#[test]
fn one_instruction_mismatch_selects_the_entire_fallback_group() {
    let (module, mut image, layout) = fixture();
    put(&mut image, 0x200, 0);
    assert_eq!(
        callbacks(&module, 0x40, &image, &layout, 2).unwrap(),
        [0x4500, 0x4520]
    );
}

#[test]
fn callback_flags_null_records_and_single_entries_follow_the_code() {
    let (mut module, mut image, layout) = fixture();
    put(&mut image, 0x200, 0);
    put(&mut module, 0x1824, 2);
    assert_eq!(
        callbacks(&module, 0x40, &image, &layout, 2).unwrap(),
        [0x4400, 0x4200]
    );
    put(&mut module, 0x1818, 0);
    assert_eq!(
        callbacks(&module, 0x40, &image, &layout, 2).unwrap(),
        [0x4400]
    );
    put(&mut module, 0x1800, 1);
    assert_eq!(
        callbacks(&module, 0x40, &image, &layout, 1).unwrap(),
        [0x4400]
    );
}

#[test]
fn unsupported_code_invalid_memory_and_excess_calls_are_rejected() {
    let (module, image, layout) = fixture();
    assert!(callbacks(&module, 0x40, &image, &layout, 1).is_err());
    for (offset, instruction) in [
        (0x100, 0xd400_0001), // system call
        (0x108, 0xf900_0413), // attempted write outside the stack
        (0x150, 0x1400_0000), // nonterminating comparison loop
        (0x1808, 0x9000),     // primary is outside the image
        (0x181c, 0x9000),     // fallback is outside the image
        (0x1800, u32::MAX),   // count exceeds the module/table bounds
    ] {
        let mut broken = module.clone();
        put(&mut broken, offset, instruction);
        let mut mismatched = image.clone();
        if offset == 0x181c {
            put(&mut mismatched, 0x200, 0);
        }
        assert!(
            callbacks(&broken, 0x40, &mismatched, &layout, 2).is_err(),
            "offset {offset:x}"
        );
    }
    assert!(callbacks(&module[..0x1820], 0x40, &image, &layout, 2).is_err());
    assert!(callbacks(&module, 0xffff_ffff, &image, &layout, 2).is_err());
}

#[test]
fn multiple_reachable_selectors_are_not_silently_chosen() {
    let (mut module, image, layout) = fixture();
    module.copy_within(0x100..0x1a4, 0x300);
    put(&mut module, 0x44, 0x9400_00af); // BL 0x300
    put(&mut module, 0x48, 0xd65f_03c0);
    assert!(
        callbacks(&module, 0x40, &image, &layout, 2)
            .unwrap_err()
            .to_string()
            .contains("2 validated")
    );
}
