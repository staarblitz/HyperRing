use crate::utils::kalloc::PhysicalAllocator;
use alloc::boxed::Box;
use core::mem::MaybeUninit;
use wdk_sys::{
    RTL_BITMAP,
    ntddk::{
        RtlClearAllBits,
        RtlInitializeBitMap,
    },
};

#[repr(C, align(4096))]
#[derive(Copy, Clone, Debug)]
/// Describes the MsrBitmap
pub struct MsrBitmap {
    pub read_low_msrs: [u8; 0x400],
    pub read_high_msrs: [u8; 0x400],
    pub write_low_msrs: [u8; 0x400],
    pub write_high_msrs: [u8; 0x400],
}

impl MsrBitmap {
    pub fn new() -> Box<MsrBitmap, PhysicalAllocator> {
        let mut instance = Box::<Self, PhysicalAllocator>::new_zeroed_in(PhysicalAllocator);

        Self::initialize_bitmap(instance.as_mut() as *mut _ as _);

        unsafe { instance.assume_init() }
    }
    fn initialize_bitmap(bitmap_ptr: *mut u64) {
        let mut bitmap_header: MaybeUninit<RTL_BITMAP> = MaybeUninit::uninit();
        let bitmap_header_ptr = bitmap_header.as_mut_ptr() as *mut _;

        unsafe {
            RtlInitializeBitMap(
                bitmap_header_ptr as _,
                bitmap_ptr as _,
                size_of::<Self>() as u32,
            )
        }
        unsafe { RtlClearAllBits(bitmap_header_ptr as _) }
    }
}
