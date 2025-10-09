use crate::{
    intel::{
        ctrl::{
            VmxControl,
            adjust_controls,
        },
        events::VmxEvent,
        segmentation::{
            SegmentAccessRights,
            SegmentDescriptor,
        },
        vmx_def::HyperFail,
    },
    utils::kalloc::PhysicalAllocator,
};
use alloc::boxed::Box;
use core::{
    ops::BitAnd,
    ptr::null_mut,
};
use wdk::println;
use wdk_sys::{
    CONTEXT,
    PVOID,
    ntddk::{
        KeGetCurrentProcessorNumberEx,
        MmGetPhysicalAddress,
    },
};
use x86::{
    bits64::{
        registers::{
            rip,
            rsp,
        },
        vmx::{
            vmclear,
            vmlaunch,
            vmptrld,
            vmread,
            vmresume,
            vmwrite,
            vmxoff,
        },
    },
    controlregs::{
        cr0,
        cr4,
    },
    dtables::{
        DescriptorTablePointer,
        ldtr,
        sgdt,
        sidt,
    },
    int,
    msr::{
        IA32_FS_BASE,
        IA32_GS_BASE,
        IA32_SYSENTER_CS,
        IA32_SYSENTER_EIP,
        IA32_SYSENTER_ESP,
        IA32_VMX_BASIC,
        rdmsr,
    },
    segmentation::{
        SegmentSelector,
        cs,
        ds,
        es,
        fs,
        gs,
        ss,
    },
    task::tr,
    vmx,
    vmx::vmcs::control::{
        EntryControls,
        ExitControls,
        PrimaryControls,
        SecondaryControls,
    },
};

#[derive(Copy, Clone, Debug)]
#[repr(C, align(4096))]
/// Represents the VMCS region with very little abstraction.
pub struct VmcsRegion {
    /// The revision id from msr.
    pub revision_id: u32,
    /// Rest of the fields. Reserved.
    pub reserved: [u8; 4092],
}

#[derive(Debug)]
/// Provides access and abstraction to control a VM.
pub struct VmxCtrl {
    /// The VMCS region.
    pub vmcs: Box<VmcsRegion, PhysicalAllocator>,
    /// Physical address of the VMCS region.
    pub vmcs_phys: u64,
}

impl VmxCtrl {
    /// Sets up a new VMCS.
    pub fn setup() -> Result<Self, HyperFail> {
        unsafe {
            println!("[VMCS] Allocating physical memory for VMCS.");
            let mut vmcs: Box<VmcsRegion, PhysicalAllocator> =
                Box::try_new_zeroed_in(PhysicalAllocator)
                    .unwrap()
                    .assume_init();

            let phys_addr =
                MmGetPhysicalAddress(vmcs.as_mut() as *mut VmcsRegion as PVOID).QuadPart as u64;

            println!(
                "[VMCS] Allocated memory: V{:x}, P{:x}.",
                vmcs.as_mut() as *mut VmcsRegion as u64,
                phys_addr
            );

            vmcs.revision_id = rdmsr(IA32_VMX_BASIC) as u32;
            println!("[VMCS] Revision id: {:x}.", vmcs.revision_id);

            Ok(Self {
                vmcs: vmcs,
                vmcs_phys: phys_addr,
            })
        }
    }

    /// Injects desired event with optional error code into guest.
    pub fn inject_event(error_code: Option<u64>, event: VmxEvent) {
        if let Some(error_code) = error_code {
            Self::write(vmx::vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, error_code);
        }

        Self::write(
            vmx::vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
            event.into_bits(),
        );

        // Advance the instruction.
        let instr_len = unsafe { vmread(vmx::vmcs::ro::VMEXIT_INSTRUCTION_LEN) }.unwrap();
        Self::write(vmx::vmcs::control::VMENTRY_INSTRUCTION_LEN, instr_len);
    }

    /// Deprecated. It was inlined for maximum accuracy.
    pub fn launch(&self) -> Result<(), HyperFail> {
        unsafe {
            println!(
                "[VMCS] Launching processor {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            let result = vmlaunch();
            if result.is_err() {
                println!(
                    "[VMCS] Error launching processor {}",
                    KeGetCurrentProcessorNumberEx(null_mut())
                );
                return HyperFail::from_vm_fail(result.unwrap_err());
            }
            println!(
                "[VMCS] Launched processor {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Ok(())
        }
    }

    pub fn clear(&self) -> Result<(), HyperFail> {
        unsafe {
            println!(
                "[VMCS] Clearing {:x} for processor {}",
                self.vmcs_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            let result = vmclear(self.vmcs_phys);
            if result.is_err() {
                println!(
                    "[VMCS] Error clearing {:x} for processor {}",
                    self.vmcs_phys,
                    KeGetCurrentProcessorNumberEx(null_mut())
                );
                return HyperFail::from_vm_fail(result.unwrap_err());
            }
            println!(
                "[VMCS] Cleared {:x} for processor {}",
                self.vmcs_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Ok(())
        }
    }

    pub fn load(&self) -> Result<(), HyperFail> {
        unsafe {
            println!(
                "[VMCS] Loading from {:x} for processor {}",
                self.vmcs_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            let result = vmptrld(self.vmcs_phys);
            if result.is_err() {
                println!(
                    "[VMCS] Error loading from {:x} for processor {}",
                    self.vmcs_phys,
                    KeGetCurrentProcessorNumberEx(null_mut())
                );
                return HyperFail::from_vm_fail(result.unwrap_err());
            }
            println!(
                "[VMCS] Loaded from {:x} for processor {}",
                self.vmcs_phys,
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Ok(())
        }
    }

    #[unsafe(no_mangle)]
    /// Increments RIP of the guest.
    pub fn vm_increment_rip(&self) {
        unsafe {
            let mut resume_rip = vmread(vmx::vmcs::guest::RIP).unwrap();
            let exit_instruction_len = vmread(vmx::vmcs::ro::VMEXIT_INSTRUCTION_LEN).unwrap();

            let pid = KeGetCurrentProcessorNumberEx(null_mut());
            println!(
                "[VMEXIT] Incrementing rip from {:x} to {:x} for processor {}",
                resume_rip,
                resume_rip + exit_instruction_len,
                pid
            );

            resume_rip += exit_instruction_len;
            vmwrite(vmx::vmcs::guest::RIP, resume_rip).unwrap();
        }
    }

    #[unsafe(no_mangle)]
    /// Called by vm_exit_handler. Reports failure upon vmresume.
    pub fn vmresume_failed() {
        let error = unsafe { vmread(vmx::vmcs::ro::VM_INSTRUCTION_ERROR) };
        let pid = unsafe { KeGetCurrentProcessorNumberEx(null_mut()) };
        println!(
            "[VMEXIT] VMRESUME for processor {} failed due to {}",
            pid,
            error.unwrap()
        );
    }

    #[unsafe(no_mangle)]
    /// Obsolete. Handled by vm_exit_handler instead.
    pub fn vm_resume() {
        unsafe {
            let pid = KeGetCurrentProcessorNumberEx(null_mut());
            println!(
                "[VMEXIT] VMRESUME for processor {}. RSP {:x}, RIP {:x}",
                pid,
                rsp(),
                rip()
            );
            let result = vmresume();
            if result.is_err() {
                int!(0x3);
                let fail = HyperFail::from_vm_fail(result.unwrap_err());
                println!(
                    "[VMEXIT] Failed to resume processor {}",
                    fail.unwrap_err().failure_const
                );
                vmxoff();
            }
        }
    }

    /// Abstraction over vmwrite.
    fn write<T: Into<u64>>(field: u32, val: T)
    where
        u64: From<T>,
    {
        let value = u64::from(val);
        unsafe {
            if let Err(err) = vmwrite(field, value) {
                println!(
                    "[VMCS] Failed to write field {:x} with value {:x} due to {:x}",
                    field,
                    value,
                    HyperFail::from_vm_fail(err).unwrap_err().failure_const
                );
            }
        }
    }

    #[allow(unused_must_use)]
    #[allow(unused_results)]
    #[unsafe(no_mangle)]
    /// Fills guest's control area.
    pub fn fill_control_area(&self, msr_phys_addr: u64) {
        unsafe {
            println!(
                "[VMCS] Begin init control field: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Self::write(
                vmx::vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                adjust_controls(
                    VmxControl::ProcessorBased,
                    (PrimaryControls::USE_MSR_BITMAPS.bits()
                        | PrimaryControls::SECONDARY_CONTROLS.bits()) as u64,
                ),
            );

            Self::write(
                vmx::vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
                adjust_controls(
                    VmxControl::ProcessorBased2,
                    (SecondaryControls::ENABLE_RDTSCP.bits()
                        | SecondaryControls::ENABLE_INVPCID.bits()
                        | SecondaryControls::ENABLE_XSAVES_XRSTORS.bits()
                        | SecondaryControls::ENABLE_USER_WAIT_PAUSE.bits())
                        as u64,
                ),
            );

            Self::write(
                vmx::vmcs::control::PINBASED_EXEC_CONTROLS,
                adjust_controls(VmxControl::PinBased, 0),
            );

            Self::write(vmx::vmcs::control::CR0_READ_SHADOW, cr0().bits() as u64);
            Self::write(vmx::vmcs::control::CR4_READ_SHADOW, cr4().bits() as u64);

            Self::write(vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_phys_addr);

            // Exit on all exceeptions
            Self::write(vmx::vmcs::control::EXCEPTION_BITMAP, u64::MAX);

            Self::write(
                vmx::vmcs::control::VMEXIT_CONTROLS,
                adjust_controls(
                    VmxControl::VmExit,
                    ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64,
                ),
            );
            Self::write(
                vmx::vmcs::control::VMENTRY_CONTROLS,
                adjust_controls(
                    VmxControl::VmEntry,
                    EntryControls::IA32E_MODE_GUEST.bits() as u64,
                ),
            );

            Self::write(vmx::vmcs::control::MSR_BITMAPS_ADDR_FULL, msr_phys_addr);

            println!(
                "[VMCS] End init control field: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
        }
    }

    #[allow(unused_must_use)]
    #[allow(unused_results)]
    #[unsafe(no_mangle)]
    /// Fill's host specific fields.
    pub fn fill_host_area(&self, vmm_stack: u64) {
        unsafe {
            println!(
                "[VMCS] Begin init host area: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );

            Self::write(vmx::vmcs::host::CR0, x86::controlregs::cr0().bits() as u64);
            Self::write(vmx::vmcs::host::CR3, x86::controlregs::cr3());
            Self::write(vmx::vmcs::host::CR4, x86::controlregs::cr4().bits() as u64);

            Self::write(vmx::vmcs::host::ES_SELECTOR, es().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::CS_SELECTOR, cs().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::SS_SELECTOR, ss().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::DS_SELECTOR, ds().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::FS_SELECTOR, fs().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::GS_SELECTOR, gs().bits().bitand(0xF8));
            Self::write(vmx::vmcs::host::TR_SELECTOR, tr().bits().bitand(0xF8));

            let mut gdt = DescriptorTablePointer::<u64>::default();
            sgdt(&mut gdt);

            let mut idt = DescriptorTablePointer::<u64>::default();
            sidt(&mut idt);

            let descriptor = SegmentDescriptor::from_selector(tr(), &gdt);
            Self::write(vmx::vmcs::host::GS_BASE, rdmsr(IA32_GS_BASE));
            Self::write(vmx::vmcs::host::FS_BASE, rdmsr(IA32_FS_BASE));
            Self::write(vmx::vmcs::host::TR_BASE, descriptor.base);

            Self::write(vmx::vmcs::host::GDTR_BASE, gdt.base as u64);
            Self::write(vmx::vmcs::host::IDTR_BASE, idt.base as u64);

            Self::write(vmx::vmcs::host::IA32_SYSENTER_CS, rdmsr(IA32_SYSENTER_CS));
            Self::write(vmx::vmcs::host::IA32_SYSENTER_ESP, rdmsr(IA32_SYSENTER_ESP));
            Self::write(vmx::vmcs::host::IA32_SYSENTER_EIP, rdmsr(IA32_SYSENTER_EIP));

            Self::write(vmx::vmcs::host::RSP, vmm_stack);
            Self::write(
                vmx::vmcs::host::RIP,
                crate::intel::vm::exit_handler::vm_exit_handler as *const u64 as u64,
            );

            println!(
                "[VMCS] End init host area: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
        }
    }

    #[allow(unused_must_use)]
    #[allow(unused_results)]
    #[unsafe(no_mangle)]
    /// Fills guest specific fields.
    pub fn fill_guest_area(&self, guest_regs: &CONTEXT) {
        unsafe {
            println!(
                "[VMCS] Begin init guest area: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
            Self::write(vmx::vmcs::guest::CR0, x86::controlregs::cr0().bits() as u64);
            Self::write(vmx::vmcs::guest::CR3, x86::controlregs::cr3());
            Self::write(vmx::vmcs::guest::CR4, x86::controlregs::cr4().bits() as u64);

            //TODO: Use a custom GDT and IDT for better isolation.

            let mut gdt = DescriptorTablePointer::<u64>::default();
            sgdt(&mut gdt);

            let mut idt = DescriptorTablePointer::<u64>::default();
            sidt(&mut idt);

            let mut descriptor = SegmentDescriptor::from_selector(cs(), &gdt);
            Self::write(vmx::vmcs::guest::CS_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::CS_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::CS_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(ss(), &gdt);
            Self::write(vmx::vmcs::guest::SS_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::SS_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::SS_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(ds(), &gdt);
            Self::write(vmx::vmcs::guest::DS_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::DS_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::DS_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(es(), &gdt);
            Self::write(vmx::vmcs::guest::ES_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::ES_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::ES_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(fs(), &gdt);
            Self::write(vmx::vmcs::guest::FS_BASE, rdmsr(IA32_FS_BASE));
            Self::write(vmx::vmcs::guest::FS_SELECTOR, descriptor.base);
            Self::write(vmx::vmcs::guest::FS_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::FS_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(gs(), &gdt);
            Self::write(vmx::vmcs::guest::GS_BASE, rdmsr(IA32_GS_BASE));
            Self::write(vmx::vmcs::guest::GS_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::GS_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::GS_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(tr(), &gdt);
            Self::write(vmx::vmcs::guest::TR_BASE, descriptor.base);
            Self::write(vmx::vmcs::guest::TR_SELECTOR, descriptor.selector.bits());
            Self::write(vmx::vmcs::guest::TR_LIMIT, descriptor.limit);
            Self::write(vmx::vmcs::guest::TR_ACCESS_RIGHTS, descriptor.access_rights);

            descriptor = SegmentDescriptor::from_selector(ldtr(), &gdt);
            Self::write(vmx::vmcs::guest::LDTR_SELECTOR, descriptor.selector.bits());
            Self::write(
                vmx::vmcs::guest::LDTR_ACCESS_RIGHTS,
                SegmentAccessRights::from_selector(SegmentSelector::from_raw(0)),
            );

            Self::write(vmx::vmcs::guest::IDTR_BASE, idt.base as u64);
            Self::write(vmx::vmcs::guest::IDTR_LIMIT, idt.limit as u64);

            Self::write(vmx::vmcs::guest::GDTR_BASE, gdt.base as u64);
            Self::write(vmx::vmcs::guest::GDTR_LIMIT, gdt.limit as u64);

            Self::write(vmx::vmcs::guest::IA32_SYSENTER_CS, rdmsr(IA32_SYSENTER_CS));
            Self::write(
                vmx::vmcs::guest::IA32_SYSENTER_ESP,
                rdmsr(IA32_SYSENTER_ESP),
            );
            Self::write(
                vmx::vmcs::guest::IA32_SYSENTER_EIP,
                rdmsr(IA32_SYSENTER_EIP),
            );

            Self::write(vmx::vmcs::guest::LINK_PTR_FULL, u64::MAX);

            Self::write(vmx::vmcs::guest::RSP, guest_regs.Rsp);
            Self::write(vmx::vmcs::guest::RIP, guest_regs.Rip);
            Self::write(vmx::vmcs::guest::RFLAGS, guest_regs.EFlags);

            println!(
                "[VMCS] End init guest area: {}",
                KeGetCurrentProcessorNumberEx(null_mut())
            );
        }
    }
}
