use crate::{
    intel::vmx_def::HyperFail,
    utils::kalloc::PhysicalAllocator,
};
use alloc::boxed::Box;
use core::{
    ops::BitAnd,
    ptr::null_mut,
};
use wdk::println;
use wdk_sys::{
    PVOID,
    STATUS_HV_OPERATION_FAILED,
    ntddk::{
        KeGetCurrentProcessorNumberEx,
        MmGetPhysicalAddress,
    },
};
use x86::{
    bits64::vmx::vmxon,
    controlregs::{
        Cr0,
        Cr4,
        cr0,
        cr0_write,
        cr4,
        cr4_write,
    },
    msr::{
        IA32_FEATURE_CONTROL,
        IA32_VMX_BASIC,
        IA32_VMX_CR0_FIXED0,
        IA32_VMX_CR0_FIXED1,
        IA32_VMX_CR4_FIXED0,
        IA32_VMX_CR4_FIXED1,
        rdmsr,
    },
};

#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
/// Represents VMXON region with very small level of abstraction.
pub struct VmxOnRegion {
    /// The revision id from MSR.
    pub revision_id: u32,
    /// Reserved, rest of the VMXON.
    pub reserved: [u8; 4092],
}

#[derive(Debug)]
/// Represents abstraction over VMXON region.
pub struct VmxOnData {
    /// The allocated VmxOnRegion.
    pub vmxon: Box<VmxOnRegion, PhysicalAllocator>,
    /// Physical address of the region.
    pub vmxon_phys: u64,
}

impl VmxOnData {
    pub fn setup() -> Result<VmxOnData, HyperFail> {
        unsafe {
            println!("[VMXON] Allocating physical memory for VMXON.");
            let mut vmxon: Box<VmxOnRegion, PhysicalAllocator> =
                Box::try_new_zeroed_in(PhysicalAllocator)
                    .unwrap()
                    .assume_init();

            let phys_addr =
                MmGetPhysicalAddress(vmxon.as_mut() as *mut VmxOnRegion as PVOID).QuadPart as u64;

            println!(
                "[VMXON] Allocated memory: V{:x}, P{:x}.",
                vmxon.as_mut() as *mut VmxOnRegion as u64,
                phys_addr
            );

            vmxon.revision_id = rdmsr(IA32_VMX_BASIC) as u32;
            println!("[VMXON] Revision id: {:x}.", vmxon.revision_id);

            Ok(Self {
                vmxon: vmxon,
                vmxon_phys: phys_addr,
            })
        }
    }

    /// This function sets the VMX lock bits as described in Intel's software developer manual.
    fn set_lock_bit() -> Result<(), HyperFail> {
        unsafe {
            const VMX_LOCK_BIT: u64 = 1 << 0;
            const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

            let ia32_feature_control = rdmsr(IA32_FEATURE_CONTROL);

            if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
                x86::msr::wrmsr(
                    IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                );
            } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
                return HyperFail::from_nt_fail(STATUS_HV_OPERATION_FAILED);
            }

            Ok(())
        }
    }

    /// This function ensures CR0 is setup properly for VMX operation.
    fn set_cr0_bits() {
        unsafe {
            let mut cr0 = cr0().bits();

            cr0 |= rdmsr(IA32_VMX_CR0_FIXED0).bitand(0xFFFF_FFFF) as usize;
            cr0 &= rdmsr(IA32_VMX_CR0_FIXED1).bitand(0xFFFF_FFFF) as usize;

            cr0_write(Cr0::from_bits(cr0).unwrap());
        }
    }

    /// This function ensures CR4 is setup properly for VMX operation.
    fn set_cr4_bits() {
        unsafe {
            let mut cr4 = cr4().bits();

            cr4 |= rdmsr(IA32_VMX_CR4_FIXED0).bitand(0xFFFF_FFFF) as usize;
            cr4 &= rdmsr(IA32_VMX_CR4_FIXED1).bitand(0xFFFF_FFFF) as usize;

            cr4_write(Cr4::from_bits(cr4).unwrap());
        }
    }

    /// This function enables VMX mode for the currently running CPU.
    pub fn on(&self) -> Result<(), HyperFail> {
        unsafe {
            println!("[VMXON] Enabling VMXON.");
            cr4_write(cr4() | Cr4::CR4_ENABLE_VMX);

            println!("[VMXON] Locking VMX bit.");
            let result = Self::set_lock_bit();
            if result.is_err() {
                println!("[VMXON] Failed locking VMX bit.");
                return result;
            }

            println!("[VMXON] Fixing CR0");
            Self::set_cr0_bits();
            println!("[VMXON] Fixing CR4");
            Self::set_cr4_bits();

            println!(
                "[VMXON] Loading VMXON from {:x} for {:x}",
                self.vmxon_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            let result = vmxon(self.vmxon_phys);
            if let Err(err) = result {
                println!(
                    "[VMXON] Error loading VMXON from {:x} for {:x}",
                    self.vmxon_phys,
                    KeGetCurrentProcessorNumberEx(null_mut())
                );
                return HyperFail::from_vm_fail(err);
            }
            println!(
                "[VMXON] Loaded VMXON from {:x} for {:x}",
                self.vmxon_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Ok(())
        }
    }
}
