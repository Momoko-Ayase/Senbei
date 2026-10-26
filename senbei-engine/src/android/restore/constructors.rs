//! Evaluate the callback selector reached from the handoff module entry.
//!
//! This is a bounded interpreter for the selector's integer/control-flow
//! instructions, not a native module loader. Only stack writes are permitted;
//! image calls are recorded, never executed. Unknown instructions or memory
//! accesses reject a candidate. Table offsets, ordering, flags and the group
//! fallback decision consequently come from the module's own code.

use std::collections::{BTreeSet, HashSet};

use senbei_elf::{ElfLayout, read_u32, slice_u64};

use super::error::{Result, invalid};
use super::pipeline::{aarch64_adrp_target, virtual_address_to_file_offset};

const RUNTIME: u64 = 1 << 32;
const IMAGE: u64 = 2 << 32;
const STACK: u64 = 3 << 32;
const STACK_SIZE: usize = 0x10000;
const RETURN: u64 = u64::MAX - 3;

#[cfg(test)]
#[path = "constructors_tests.rs"]
mod tests;

fn signed(value: u32, bits: u32) -> i64 {
    i64::from((value << (32 - bits)) as i32 >> (32 - bits))
}

fn branch_target(pc: u64, instruction: u32, bits: u32, shift: u32) -> Option<u64> {
    pc.checked_add_signed(signed((instruction >> shift) & ((1 << bits) - 1), bits) * 4)
}

/// Follow direct control flow from the descriptor entry, without inspecting
/// unrelated code or searching the data image for plausible tables.
fn selector_functions(module: &[u8], entry: u32) -> Result<BTreeSet<u64>> {
    let mut functions = vec![u64::from(entry)];
    let mut visited_functions = HashSet::new();
    let mut selectors = BTreeSet::new();
    let mut budget = 100_000_usize;
    while let Some(function) = functions.pop() {
        if !visited_functions.insert(function) {
            continue;
        }
        let mut pending = vec![function];
        let mut visited = HashSet::new();
        while let Some(pc) = pending.pop() {
            if !visited.insert(pc) {
                continue;
            }
            if budget == 0 {
                return invalid("constructor module control flow exceeds analysis budget");
            }
            budget -= 1;
            let Some(instruction) = usize::try_from(pc)
                .ok()
                .filter(|offset| offset.is_multiple_of(4))
                .and_then(|offset| read_u32(module, offset).ok())
            else {
                return invalid("constructor module branches outside its image");
            };
            if instruction & 0x7c00_0000 == 0x1400_0000 {
                let Some(target) = branch_target(pc, instruction, 26, 0) else {
                    return invalid("constructor module branch address overflows");
                };
                if instruction & 0x8000_0000 != 0 {
                    functions.push(target);
                    pending.push(pc + 4);
                } else {
                    pending.push(target);
                }
                continue;
            }
            let conditional_bits = if instruction & 0xff00_0010 == 0x5400_0000
                || instruction & 0x7e00_0000 == 0x3400_0000
            {
                Some(19)
            } else if instruction & 0x7e00_0000 == 0x3600_0000 {
                Some(14)
            } else {
                None
            };
            if let Some(bits) = conditional_bits {
                let Some(target) = branch_target(pc, instruction, bits, 5) else {
                    return invalid("constructor module conditional branch overflows");
                };
                pending.push(target);
            }
            if instruction & 0xffff_fc1f == 0xd63f_0000 {
                selectors.insert(function);
            } else if instruction & 0xffff_fc1f == 0xd61f_0000
                || instruction & 0xffff_fc1f == 0xd65f_0000
                || instruction == 0
            {
                continue;
            }
            pending.push(pc + 4);
        }
    }
    Ok(selectors)
}

fn mask(bits: u32) -> u64 {
    u64::MAX >> (64 - bits)
}

fn logical_immediate(instruction: u32, width: u32) -> Option<u64> {
    let n = (instruction >> 22) & 1;
    let imms = (instruction >> 10) & 63;
    let immr = (instruction >> 16) & 63;
    let encoded = (n << 6) | (!imms & 63);
    let len = 31_u32.checked_sub(encoded.leading_zeros())?;
    if len < 1 || (width == 32 && n != 0) {
        return None;
    }
    let size = 1 << len;
    let ones = (imms & (size - 1)) + 1;
    if ones == size || size > width {
        return None;
    }
    let rotate = immr & (size - 1);
    let value = mask(ones);
    let element = if rotate == 0 {
        value
    } else {
        ((value >> rotate) | (value << (size - rotate))) & mask(size)
    };
    let mut result = 0;
    for position in (0..width).step_by(size as usize) {
        result |= element << position;
    }
    Some(result)
}

struct Selector<'a> {
    module: &'a [u8],
    image: &'a [u8],
    layout: &'a ElfLayout,
    registers: [Option<u64>; 31],
    sp: u64,
    stack: Vec<Option<u8>>,
    flags: Option<(bool, bool, bool, bool)>,
    read_image_base: bool,
    calls: Vec<u64>,
}

impl Selector<'_> {
    fn reg(&self, index: u32, sp: bool) -> Option<u64> {
        if index == 31 {
            Some(if sp { self.sp } else { 0 })
        } else {
            self.registers[index as usize]
        }
    }

    fn set(&mut self, index: u32, value: u64, width: u32, sp: bool) {
        let value = value & mask(width);
        if index != 31 {
            self.registers[index as usize] = Some(value);
        } else if sp {
            self.sp = value;
        }
    }

    fn read(&mut self, address: u64, size: usize) -> Option<u64> {
        if address == RUNTIME + 8 && size == 8 {
            self.read_image_base = true;
            return Some(IMAGE);
        }
        let bytes = if address >= STACK {
            let start = usize::try_from(address - STACK).ok()?;
            self.stack
                .get(start..start.checked_add(size)?)?
                .iter()
                .copied()
                .collect::<Option<Vec<_>>>()?
        } else if address >= IMAGE {
            let offset = virtual_address_to_file_offset(self.layout, address - IMAGE, size as u64)?;
            self.image.get(offset..offset.checked_add(size)?)?.to_vec()
        } else {
            slice_u64(self.module, address, size as u64).ok()?.to_vec()
        };
        Some(bytes.iter().enumerate().fold(0, |value, (index, byte)| {
            value | (u64::from(*byte) << (index * 8))
        }))
    }

    fn write(&mut self, address: u64, size: usize, value: u64) -> Option<()> {
        let offset = usize::try_from(address.checked_sub(STACK)?).ok()?;
        for (index, byte) in self
            .stack
            .get_mut(offset..offset.checked_add(size)?)?
            .iter_mut()
            .enumerate()
        {
            *byte = Some((value >> (index * 8)) as u8);
        }
        Some(())
    }

    fn condition(&self, condition: u32) -> Option<bool> {
        let (negative, zero, carry, overflow) = self.flags?;
        let matched = match condition >> 1 {
            0 => zero,
            1 => carry,
            2 => negative,
            3 => overflow,
            4 => carry && !zero,
            5 => negative == overflow,
            6 => negative == overflow && !zero,
            7 => return Some(true),
            _ => return None,
        };
        Some(matched ^ (condition & 1 != 0))
    }

    fn run(mut self, start: u64, max_calls: usize) -> Option<Vec<u64>> {
        let mut pc = start;
        let budget = max_calls
            .checked_add(1)?
            .checked_mul(256)?
            .checked_add(1024)?
            .min(1_000_000);
        for _ in 0..budget {
            if !pc.is_multiple_of(4) {
                return None;
            }
            let instruction = read_u32(self.module, usize::try_from(pc).ok()?).ok()?;
            let mut next = pc.checked_add(4)?;
            let rd = instruction & 31;
            let rn = (instruction >> 5) & 31;
            let width = if instruction >> 31 == 0 { 32 } else { 64 };
            if instruction & 0xffff_fc1f == 0xd65f_0000 {
                return (self.reg(rn, false)? == RETURN
                    && self.sp == STACK + STACK_SIZE as u64
                    && self.read_image_base
                    && !self.calls.is_empty()
                    && self.reg(0, false)? == 1)
                    .then_some(self.calls);
            } else if instruction & 0xffff_fc1f == 0xd63f_0000 {
                let address = self.reg(rn, false)?.checked_sub(IMAGE)?;
                if self.calls.len() >= max_calls || !executable_address(self.layout, address) {
                    return None;
                }
                self.calls.push(address);
                self.registers[..19].fill(None);
                self.registers[30] = Some(next);
                self.flags = None;
            } else if instruction & 0xfc00_0000 == 0x1400_0000 {
                next = branch_target(pc, instruction, 26, 0)?;
            } else if instruction & 0xff00_0010 == 0x5400_0000 {
                if self.condition(instruction & 15)? {
                    next = branch_target(pc, instruction, 19, 5)?;
                }
            } else if instruction & 0x7e00_0000 == 0x3400_0000 {
                let nonzero = self.reg(rd, false)? & mask(width) != 0;
                if nonzero == (instruction & (1 << 24) != 0) {
                    next = branch_target(pc, instruction, 19, 5)?;
                }
            } else if instruction & 0x9f00_0000 == 0x9000_0000 {
                self.set(rd, aarch64_adrp_target(instruction, pc)?, 64, false);
            } else if instruction & 0x1f80_0000 == 0x1280_0000 {
                let shift = ((instruction >> 21) & 3) * 16;
                if shift >= width {
                    return None;
                }
                let immediate = u64::from((instruction >> 5) & 0xffff) << shift;
                let value = match (instruction >> 29) & 3 {
                    0 => !immediate,
                    2 => immediate,
                    3 => (self.reg(rd, false)? & !(0xffff_u64 << shift)) | immediate,
                    _ => return None,
                };
                self.set(rd, value, width, false);
            } else if instruction & 0x1f00_0000 == 0x1100_0000
                || instruction & 0x1f20_0000 == 0x0b00_0000
            {
                let immediate = instruction & 0x1f00_0000 == 0x1100_0000;
                let left = self.reg(rn, immediate)? & mask(width);
                let right = if immediate {
                    u64::from((instruction >> 10) & 0xfff)
                        << (if instruction & (1 << 22) != 0 { 12 } else { 0 })
                } else {
                    if (instruction >> 22) & 3 != 0 {
                        return None;
                    }
                    let shift = (instruction >> 10) & 63;
                    if shift >= width {
                        return None;
                    }
                    (self.reg((instruction >> 16) & 31, false)? << shift) & mask(width)
                };
                let subtract = instruction & (1 << 30) != 0;
                let set_flags = instruction & (1 << 29) != 0;
                let value = if subtract {
                    left.wrapping_sub(right)
                } else {
                    left.wrapping_add(right)
                } & mask(width);
                if set_flags {
                    let sign = 1_u64 << (width - 1);
                    let carry = if subtract {
                        left >= right
                    } else {
                        u128::from(left) + u128::from(right) > u128::from(mask(width))
                    };
                    let overflow = if subtract {
                        (left ^ right) & (left ^ value) & sign != 0
                    } else {
                        !(left ^ right) & (left ^ value) & sign != 0
                    };
                    self.flags = Some((value & sign != 0, value == 0, carry, overflow));
                }
                self.set(rd, value, width, immediate && !set_flags);
            } else if instruction & 0x1f80_0000 == 0x1200_0000
                || instruction & 0x1f20_0000 == 0x0a00_0000
            {
                let left = self.reg(rn, false)?;
                let right = if instruction & 0x1f80_0000 == 0x1200_0000 {
                    logical_immediate(instruction, width)?
                } else {
                    if (instruction >> 22) & 3 != 0 {
                        return None;
                    }
                    let shift = (instruction >> 10) & 63;
                    if shift >= width {
                        return None;
                    }
                    self.reg((instruction >> 16) & 31, false)? << shift
                };
                let value = match (instruction >> 29) & 3 {
                    0 => left & right,
                    1 => left | right,
                    2 => left ^ right,
                    _ => return None,
                };
                self.set(rd, value, width, false);
            } else if instruction & 0x7f80_0000 == 0x5300_0000 {
                let rotate = (instruction >> 16) & 63;
                let end = (instruction >> 10) & 63;
                if rotate >= width || end >= width || (instruction >> 22) & 1 != width / 64 {
                    return None;
                }
                let source = self.reg(rn, false)? & mask(width);
                let value = if rotate <= end {
                    (source >> rotate) & mask(end - rotate + 1)
                } else {
                    (source & mask(end + 1)) << (width - rotate)
                };
                self.set(rd, value, width, false);
            } else if instruction & 0x3b00_0000 == 0x3900_0000 && instruction & (1 << 26) == 0 {
                let size = 1_usize << (instruction >> 30);
                let address = self
                    .reg(rn, true)?
                    .checked_add(u64::from((instruction >> 10) & 0xfff) * size as u64)?;
                match (instruction >> 22) & 3 {
                    0 => self.write(address, size, self.reg(rd, false)?)?,
                    1 => {
                        let value = self.read(address, size)?;
                        self.set(rd, value, if size == 8 { 64 } else { 32 }, false);
                    }
                    _ => return None,
                }
            } else {
                return None;
            }
            pc = next;
        }
        None
    }
}

pub(super) fn executable_address(layout: &ElfLayout, address: u64) -> bool {
    address.is_multiple_of(4)
        && layout.program_headers.iter().any(|segment| {
            segment.flags & 1 != 0
                && address >= segment.virtual_address
                && address
                    .checked_add(4)
                    .zip(segment.virtual_address.checked_add(segment.file_size))
                    .is_some_and(|(end, limit)| end <= limit)
        })
}

pub(super) fn callbacks(
    module: &[u8],
    entry: u32,
    image: &[u8],
    layout: &ElfLayout,
    max_calls: usize,
) -> Result<Vec<u64>> {
    let mut matches = Vec::new();
    for function in selector_functions(module, entry)? {
        let mut registers = [None; 31];
        registers[0] = Some(RUNTIME);
        registers[30] = Some(RETURN);
        let selector = Selector {
            module,
            image,
            layout,
            registers,
            sp: STACK + STACK_SIZE as u64,
            stack: vec![None; STACK_SIZE],
            flags: None,
            read_image_base: false,
            calls: Vec::new(),
        };
        if let Some(calls) = selector.run(function, max_calls) {
            matches.push(calls);
        }
    }
    match matches.len() {
        1 => Ok(matches.pop().unwrap()),
        count => invalid(format!(
            "constructor module entry reaches {count} validated callback selectors"
        )),
    }
}
