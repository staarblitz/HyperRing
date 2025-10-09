use bitfields::bitfield;
use x86::{
    bits64::rflags::RFlags,
    dtables::DescriptorTablePointer,
    segmentation::SegmentSelector,
};

#[repr(C, align(16))]
#[derive(Copy, Clone)]
/// Describes a segment in the beautiful way.
pub struct SegmentDescriptor {
    pub selector: SegmentSelector,
    pub base: u64,
    pub limit: u32,
    pub access_rights: SegmentAccessRights,
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct SegmentAttributes {
    #[bits(16)]
    pub limit_low: u32,
    #[bits(24)]
    pub base_low: u32,

    pub accessed: bool,
    pub writable: bool,
    pub conforming: bool,
    pub executable: bool,
    pub segment_type: bool,
    #[bits(2)]
    pub dpl: u8,
    pub present: bool,

    #[bits(4)]
    pub limit_high: u32,

    pub available: bool,
    pub long_mode: bool,
    pub default_size: bool,
    pub granularity: bool,

    pub base_high: u8,
}

#[derive(Copy, Clone, Default)]
pub struct SegmentAccessRights(u32);

impl SegmentAccessRights {
    fn load_access_rights(selector: SegmentSelector) -> u32 {
        let flags: u64;
        let mut access_rights: u64;
        unsafe {
            core::arch::asm!(
            "lar {}, {}",
            "pushfq",
            "pop {}",
            out(reg) access_rights,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
            );
        };
        if RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF) {
            access_rights as _
        } else {
            0
        }
    }
    pub fn from_selector(segment_selector: SegmentSelector) -> Self {
        let ar = Self::load_access_rights(segment_selector);
        if ar == 0 {
            return SegmentAccessRights(1 << 16);
        }

        // This is the format VMX understands an access right as.
        Self((ar >> 8) & 0b1111_0000_1111_1111)
    }
}

impl From<SegmentAccessRights> for u64 {
    fn from(value: SegmentAccessRights) -> Self {
        value.0 as u64
    }
}

impl SegmentDescriptor {
    pub const fn invalid() -> Self {
        Self {
            selector: SegmentSelector::empty(),
            base: 0,
            limit: 0,
            access_rights: SegmentAccessRights(0),
        }
    }

    fn load_segment_limit(selector: SegmentSelector) -> u32 {
        let flags: u64;
        let mut limit: u64;
        unsafe {
            core::arch::asm!(
            "lsl {}, {}",
            "pushfq",
            "pop {}",
            out(reg) limit,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
            );
        };
        if RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF) {
            limit as _
        } else {
            0
        }
    }

    pub fn from_selector(selector: SegmentSelector, gdt: &DescriptorTablePointer<u64>) -> Self {
        // Load GDT.
        let table = unsafe { core::slice::from_raw_parts(gdt.base, (gdt.limit + 1) as usize / 8) };

        // Load segment.
        let attributes = SegmentAttributes::from_bits(table[selector.index() as usize]);
        if !attributes.present() {
            return Self::invalid();
        }

        let mut base_address: u64 =
            (attributes.base_low() as u64) | (attributes.base_high() as u64) << 16;
        let mut segment_limit: u64 =
            (attributes.limit_low() as u64) | (attributes.limit_high() as u64) << 16;

        if !attributes.segment_type() {
            // If this is a user segment, the actual base is split across multiple entries. Get that too.
            let high = table[selector.index() as usize + 1];
            base_address += high << 32;
        }

        if attributes.granularity() {
            segment_limit = (segment_limit << 12) | 0xFFF;
        }

        Self {
            selector: selector,
            base: base_address,
            limit: Self::load_segment_limit(selector),
            access_rights: SegmentAccessRights::from_selector(selector),
        }
    }
}
