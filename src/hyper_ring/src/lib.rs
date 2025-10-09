#![feature(slice_ptr_get)]
#![feature(allocator_api)]
#![no_std]

extern crate alloc;
extern crate wdk_panic;

use core::ffi::c_void;
use wdk::println;
use wdk_sys::{
    ntddk::*,
    *,
};

use wdk_alloc::WdkAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

mod intel;
mod processor;
mod utils;
use crate::{
    intel::vm::hyper_status::HyperRingStatus,
    processor::*,
    utils::globals::HYPER_RING_STATUS,
};

/// The main entrypoint of the hypervisor.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn hr_driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> i32 {
    unsafe {
        // Make sure kernel debugger is aware our driver is loaded.
        x86::int!(0x03);

        driver.DriverUnload = Some(hr_driver_unload);

        let info = x86::cpuid::CpuId::new();

        // Check if we are on an Intel CPU.
        if info.get_vendor_info().unwrap().as_str() != "GenuineIntel" {
            println!("No AMD support");
            return STATUS_NOT_SUPPORTED;
        }

        let features = info.get_feature_info().unwrap();

        // Check if the CPU has VMX support.
        if !features.has_vmx() {
            println!("No vmx support");
            return STATUS_NOT_SUPPORTED;
        }

        // Create a new context so lock drops after the end of this scope.
        {
            // Acquire lock.
            let mut lock = HYPER_RING_STATUS.lock();

            // Initialize global status.
            lock.write(*HyperRingStatus::new());
            let status = lock.assume_init_mut();

            // Initialize all processors.
            let result = status.init();
            match result {
                Err(e) => {
                    println!("Failure initializing hyper_ring: {}", e.failure_const);

                    return STATUS_UNSUCCESSFUL;
                }
                _ => {}
            }

            // Self-explanatory.
            let result = status.virtualize_system();
            match result {
                Err(e) => {
                    println!("Failure virtualizing system: {}", e.failure_const);

                    return STATUS_UNSUCCESSFUL;
                }
                _ => {}
            }
        }

        // TODO: Support hot-plug for CPUs.
        KeRegisterProcessorChangeCallback(
            Some(hr_processor_change_callback),
            core::ptr::null_mut::<UINT64>() as *mut c_void,
            0,
        );

        STATUS_SUCCESS
    }
}

pub unsafe extern "C" fn hr_driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    unsafe {
        let mut lock = HYPER_RING_STATUS.lock();

        lock.assume_init_mut().deinit();
    }
}
