//! Internal PE layout discovery and image reconstruction.

mod dd8;
mod discovery;
mod image;

pub(super) use dd8::{select_dd8_formula_pe32, select_dd8_shift};
pub(super) use discovery::{
    discover_eighth_slots, find_bytecode_offset, find_lfsr_block, find_str_pos, find_tbl_pe32,
    find_v_after_pad, find_v4_offset, get_string_to_null, section_name, trial_decrypt5_u32,
};
pub(super) use image::{
    compact_memory_image_to_pe, move_pe32_imports_to_kmiat, pe32_imports_already_match_idata_layout,
};
