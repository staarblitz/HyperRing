use crate::intel::vmx_def::GuestRegisters;
use wdk_sys::{
    POOL_FLAG_NON_PAGED,
    PVOID,
    SIZE_T,
    ntddk::{
        ExAllocatePool2,
        ExFreePool,
    },
};

#[repr(C, align(16))]
#[derive(Default)]
/// Abstracts the stack used by vm_exit_handler.
pub struct VmmStack {
    // Pointer to GuestRegisters.
    pub guest_registers_ptr: u64,
    // Pointer to actual stack.
    pub stack_ptr: u64,
}

impl VmmStack {
    /// Returns a new VmmStack object.
    pub fn new() -> VmmStack {
        unsafe {
            Self {
                guest_registers_ptr: ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    size_of::<GuestRegisters>() as SIZE_T,
                    0x2009,
                ) as u64,
                stack_ptr: ExAllocatePool2(POOL_FLAG_NON_PAGED, 8192, 0x2009) as u64,
            }
        }
    }

    /// Zeroes out the data inside stack.
    pub fn zero(&mut self) {
        unsafe { core::ptr::write_bytes(self.stack_ptr as *mut u8, 0, 8192) }
    }

    // Frees the stack.
    pub fn free(&mut self) {
        unsafe {
            ExFreePool(self.stack_ptr as PVOID);
            ExFreePool(self.guest_registers_ptr as PVOID);
        }
    }
}
