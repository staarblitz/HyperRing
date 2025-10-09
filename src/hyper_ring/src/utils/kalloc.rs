use core::{
    alloc::{
        AllocError,
        Allocator,
        Layout,
    },
    ptr::NonNull,
};
use wdk::println;
use wdk_sys::{
    PHYSICAL_ADDRESS,
    ntddk::{
        MmAllocateContiguousMemory,
        MmFreeContiguousMemory,
        RtlFillMemoryNonTemporal,
    },
};

pub struct PhysicalAllocator;
unsafe impl Allocator for PhysicalAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let alloc = unsafe {
            MmAllocateContiguousMemory(layout.size() as _, PHYSICAL_ADDRESS { QuadPart: i64::MAX })
                as *mut u8
        };
        if alloc.is_null() {
            println!("Allocate contiguous memory failed");
            return Err(AllocError);
        }

        Ok(
            unsafe {
                NonNull::new_unchecked(core::slice::from_raw_parts_mut(alloc, layout.size()))
            },
        )
    }

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unsafe {
            let alloc = self.allocate(layout)?;
            RtlFillMemoryNonTemporal(alloc.as_ptr() as _, layout.size() as _, 0);

            Ok(alloc)
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            MmFreeContiguousMemory(ptr.as_ptr() as _);
        }
    }
}
