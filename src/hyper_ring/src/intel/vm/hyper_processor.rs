use crate::{
    intel::{
        msr_bitmap::MsrBitmap,
        processor::ProcessorContext,
        vmcs::VmxCtrl,
        vmm_stack::VmmStack,
        vmx_def::{
            GuestRegisters,
            HyperFail,
        },
    },
    utils::{
        globals::VIRTUALIZATION_BITMAP,
        kalloc::PhysicalAllocator,
    },
};
use alloc::boxed::Box;
use core::{
    arch::asm,
    ptr::null_mut,
    sync::atomic::Ordering,
};
use wdk::println;
use wdk_sys::{
    CONTEXT,
    PVOID,
    STATUS_MP_PROCESSOR_MISMATCH,
    ntddk::{
        KeGetCurrentProcessorNumberEx,
        MmGetPhysicalAddress,
    },
};
use x86::bits64::vmx::vmread;

#[derive(Default)]
/// Represents an abstraction for managing a virtualized CPU.
pub struct HyperProcessor {
    pub id: u32,
    pub vmcs: Option<Box<VmxCtrl>>,
    pub vmm_stack: Box<VmmStack>,
    pub msr_bitmap: Option<Box<MsrBitmap, PhysicalAllocator>>,
    pub guest_regs: Option<Box<CONTEXT>>,
}

impl HyperProcessor {
    /// Checks if current processor is virtualized.
    pub fn is_virtualized(&self) -> bool {
        let bit = 1 << self.id;

        // We are using a global bitmap so the access without a HyperProcessor instance will be easy.
        VIRTUALIZATION_BITMAP.load(Ordering::Relaxed) & bit != 0
    }

    /// Sets current processor as virtualized.
    pub fn set_virtualized(status: bool) {
        let pid = unsafe { KeGetCurrentProcessorNumberEx(null_mut()) };
        let bit = 1 << pid;

        if status {
            VIRTUALIZATION_BITMAP.fetch_or(bit, Ordering::Relaxed);
        } else {
            VIRTUALIZATION_BITMAP.fetch_and(!bit, Ordering::Relaxed);
        }
    }

    /// Does a vmlaunch to finish virtualizing processor.
    /// THE CALLER MUST SWITCH THE CONTEXT TO PROCESSOR!
    pub fn launch(&mut self) -> Result<(), HyperFail> {
        if unsafe { KeGetCurrentProcessorNumberEx(null_mut()) } != self.id {
            return HyperFail::from_nt_fail(STATUS_MP_PROCESSOR_MISMATCH);
        }

        println!("[HP] Launching processor: {}", self.id);

        Self::set_virtualized(true);

        let simplified_regs = GuestRegisters::from_context(&self.guest_regs.as_ref().unwrap());

        println!("[VMCS] Begin init VMCS: {}", unsafe {
            KeGetCurrentProcessorNumberEx(null_mut())
        });

        self.vmcs
            .as_ref()
            .unwrap()
            .fill_guest_area(&self.guest_regs.as_ref().unwrap());
        self.vmcs
            .as_ref()
            .unwrap()
            .fill_host_area(self.vmm_stack.as_mut() as *mut VmmStack as u64);

        // Get the physical address of MsrBitmap
        self.vmcs.as_ref().unwrap().fill_control_area(unsafe {
            MmGetPhysicalAddress(
                self.msr_bitmap.as_mut().unwrap().as_mut() as *mut MsrBitmap as PVOID
            )
            .QuadPart
        } as u64);

        println!("[VMCS] End init VMCS: {}", unsafe {
            KeGetCurrentProcessorNumberEx(null_mut())
        });

        // This had to be inlined for maximum accuracy
        unsafe {
            asm!(
            "
            push [r15+ 112]
            mov rax, [r15]
            mov rcx, [r15 + 8]
            mov rdx, [r15 + 16]
            mov rbx, [r15 + 24]
            mov rbp, [r15 + 32]
            mov rsi, [r15 + 40]
            mov rdi, [r15 + 48]
            mov r8, [r15 + 56]
            mov r9, [r15 + 64]
            mov r10, [r15 + 72]
            mov r11, [r15 + 80]
            mov r12, [r15 + 88]
            mov r13, [r15 + 96]
            mov r14, [r15 + 104]
            pop r15
            vmlaunch
            ", in("r15") &simplified_regs, options(nostack, preserves_flags)
            )
        }

        // If we are here that means vmlaunch have failed.

        let err = unsafe { vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) };
        println!(
            "[VMENTRY] Failed to vmlaunch for processor {} due to {}",
            self.id,
            err.unwrap()
        );

        Ok(())
    }

    /// Devirtualizes the CPU.
    /// TODO: Actually implement this.
    pub fn terminate(&mut self) {
        unsafe {
            if self.is_virtualized() {
                return;
            }

            let _ctx = ProcessorContext::switch_to_processor(self.id);

            Self::set_virtualized(false);
            let _ = x86::bits64::vmx::vmxoff();
        }
    }

    /// Initializes VMCS region, allocates stack and msr bitmap for the host.
    pub fn init(&mut self) -> Result<(), HyperFail> {
        println!("[HP] Begin initialize processor: {}", self.id);

        // We should not be interrupted.
        let ctx = ProcessorContext::switch_to_processor_and_raise(self.id);

        if self.is_virtualized() {
            println!("[HP] Processor {} already virtualized", unsafe {
                KeGetCurrentProcessorNumberEx(null_mut())
            });

            // This is not an error. Since this means the virtualization was actually successful.
            return Ok(());
        }

        self.vmm_stack = Box::new(VmmStack::new());

        self.msr_bitmap = Some(MsrBitmap::new());

        println!("[HP] Clearing VMCS.");
        let mut result = self.vmcs.as_ref().unwrap().clear();
        if result.is_err() {
            println!("[HP] Failed to clear VMCS for processor.");
            return result;
        }

        println!("[HP] Loading VMCS.");
        result = self.vmcs.as_ref().unwrap().load();
        if result.is_err() {
            println!("[HP] Failed to load VMCS for processor");
            return result;
        }

        println!("[HP] Initialized processor: {}", self.id);
        Ok(())
    }
}
