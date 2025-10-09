#![allow(unused_must_use)]

use crate::{
    intel::{
        events::VmxEvent,
        vm::hyper_processor::HyperProcessor,
        vmcs::VmxCtrl,
        vmx_def::{
            CpuidLeaf,
            FeatureBits,
            GuestRegisters,
            VmExitInterruptionInformation,
            VmxExceptionInterrupt,
            VmxExitReason,
            VmxExitResult,
            VmxMovCrAccessType,
            VmxMovCrExitQualification,
        },
    },
    utils::globals::HYPER_RING_STATUS,
};
use core::{
    arch::naked_asm,
    ops::{
        BitAnd,
        BitAndAssign,
        BitOr,
        BitOrAssign,
    },
    ptr::null_mut,
};
use wdk::println;
use wdk_sys::ntddk::KeGetCurrentProcessorNumberEx;
use x86::{
    bits64::vmx::{
        vmread,
        vmwrite,
    },
    cpuid::cpuid,
    int,
    msr::{
        rdmsr,
        wrmsr,
    },
    vmx,
};

#[unsafe(no_mangle)]
pub unsafe fn vm_exit_dispatcher(
    guest_regs: &mut GuestRegisters,
    proc: &mut HyperProcessor,
) -> VmxExitResult {
    unsafe {
        let exit_reason = vmread(vmx::vmcs::ro::EXIT_REASON).unwrap().bitand(0xFFFF);
        let exit_qualification = vmread(vmx::vmcs::ro::EXIT_QUALIFICATION).unwrap();

        let exit_reason = VmxExitReason::from_u32(exit_reason as u32).unwrap();
        let mut exit_result = VmxExitResult::IncrementRip;

        match exit_reason {
            VmxExitReason::Cpuid => {
                exit_result = handle_cpuid(guest_regs);
            }
            VmxExitReason::ControlRegisterAccesses => {
                exit_result = handle_cr_access(guest_regs, exit_qualification);
            }
            VmxExitReason::Rdmsr => {
                exit_result = handle_msr_read(guest_regs);
            }
            VmxExitReason::Wrmsr => {
                exit_result = handle_msr_write(guest_regs);
            }
            VmxExitReason::ExceptionOrNmi => {
                exit_result = handle_exception(guest_regs);
            }
            _ => {}
        }

        exit_result
    }
}

fn handle_exception(guest_regs: &mut GuestRegisters) -> VmxExitResult {
    let interruption_info_value =
        unsafe { vmread(vmx::vmcs::ro::VMEXIT_INTERRUPTION_INFO) }.unwrap();
    let interruption_error_code_value =
        unsafe { vmread(vmx::vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE) }.unwrap();

    let interruption_info = VmExitInterruptionInformation::from_u32(interruption_info_value as u32);
    let exception_interrupt = VmxExceptionInterrupt::from_bits(interruption_info.vector.into());

    match exception_interrupt {
        VmxExceptionInterrupt::GeneralProtectionFault => {
            VmxCtrl::inject_event(
                Some(interruption_error_code_value),
                VmxEvent::general_protection_fault(),
            );
        }
        VmxExceptionInterrupt::PageFault => {
            VmxCtrl::inject_event(Some(interruption_error_code_value), VmxEvent::page_fault());
        }
        VmxExceptionInterrupt::Breakpoint => {
            VmxCtrl::inject_event(None, VmxEvent::breakpoint());
        }
        VmxExceptionInterrupt::InvalidOpcode => {
            VmxCtrl::inject_event(None, VmxEvent::undefined_opcode());
        }
        _ => {}
    }

    VmxExitResult::None
}

fn handle_msr_read(guest_regs: &mut GuestRegisters) -> VmxExitResult {
    const MSR_MASK_LOW: u64 = u32::MAX as u64;
    const MSR_RANGE_LOW_END: u64 = 0x00001FFF;
    const MSR_RANGE_HIGH_START: u64 = 0xC0000000;
    const MSR_RANGE_HIGH_END: u64 = 0xC0001FFF;
    const MSR_RESERVED_RANGE_LOW: u64 = 0x40000000;
    const MSR_RESERVED_RANGE_HIGH: u64 = 0x400000F0;

    let msr_id = guest_regs.rcx;

    // This is the reserved range for Hyper-V synthetic MSRs. Accessing to non-existent MSrs throws a #GP.
    if (msr_id >= MSR_RESERVED_RANGE_LOW) && (msr_id <= MSR_RESERVED_RANGE_HIGH) {
        guest_regs.rdx = 0;
        guest_regs.rcx = 0;
        return VmxExitResult::IncrementRip;
    }

    // Check for the sanity of MSR.
    if (msr_id <= MSR_RANGE_LOW_END)
        || ((msr_id > MSR_RANGE_HIGH_START) && (msr_id <= MSR_RANGE_HIGH_END))
    {
        let msr_value = unsafe { rdmsr(msr_id as _) };
        guest_regs.rdx = msr_value >> 32;
        guest_regs.rax = msr_value & MSR_MASK_LOW;
    } else {
        guest_regs.rdx = 0;
        guest_regs.rcx = 0;
    }

    VmxExitResult::IncrementRip
}

fn handle_msr_write(guest_regs: &mut GuestRegisters) -> VmxExitResult {
    const MSR_MASK_LOW: u64 = u32::MAX as u64;
    const MSR_RANGE_LOW_END: u64 = 0x00001FFF;
    const MSR_RANGE_HIGH_START: u64 = 0xC0000000;
    const MSR_RANGE_HIGH_END: u64 = 0xC0001FFF;
    const MSR_RESERVED_RANGE_LOW: u64 = 0x40000000;
    const MSR_RESERVED_RANGE_HIGH: u64 = 0x400000F0;

    let msr_id = guest_regs.rcx;

    // This is the reserved range for Hyper-V synthetic MSRs. Accessing to non-existent MSrs throws a #GP.
    if (msr_id >= MSR_RESERVED_RANGE_LOW) && (msr_id <= MSR_RESERVED_RANGE_HIGH) {
        guest_regs.rdx = 0;
        guest_regs.rcx = 0;
        return VmxExitResult::IncrementRip;
    }

    // Check for the sanity of the MSR.
    if (msr_id <= MSR_RANGE_LOW_END)
        || ((msr_id >= MSR_RANGE_HIGH_START) && (msr_id <= MSR_RANGE_HIGH_END))
    {
        let msr_value = (guest_regs.rdx << 32) | (guest_regs.rax & MSR_MASK_LOW);
        unsafe {
            wrmsr(msr_id as _, msr_value);
        };
    } else {
        guest_regs.rdx = 0;
        guest_regs.rcx = 0;
    }

    VmxExitResult::IncrementRip
}

fn handle_cr_access(guest_regs: &mut GuestRegisters, exit_qualification: u64) -> VmxExitResult {
    unsafe {
        let data = VmxMovCrExitQualification::from_bits(*(exit_qualification as *mut u64));
        let reg_ptr = (guest_regs.rax + data.register() as u64) as *mut u64;

        if data.register() == 4 {
            *reg_ptr = vmread(vmx::vmcs::guest::RSP).unwrap();
        }

        match data.access_type() {
            VmxMovCrAccessType::MovToCr => match data.control_register() {
                0 => {
                    vmwrite(vmx::vmcs::guest::CR0, *reg_ptr);
                    vmwrite(vmx::vmcs::control::CR0_READ_SHADOW, *reg_ptr);
                }
                3 => {
                    vmwrite(vmx::vmcs::guest::CR3, *reg_ptr & (!1 << 63));
                }
                4 => {
                    vmwrite(vmx::vmcs::guest::CR4, *reg_ptr);
                    vmwrite(vmx::vmcs::control::CR4_READ_SHADOW, *reg_ptr);
                }
                _ => unreachable!(),
            },
            VmxMovCrAccessType::MovFromCr => match data.control_register() {
                0 => {
                    *reg_ptr = vmread(vmx::vmcs::guest::CR0).unwrap();
                }
                3 => {
                    *reg_ptr = vmread(vmx::vmcs::guest::CR3).unwrap();
                }
                4 => {
                    *reg_ptr = vmread(vmx::vmcs::guest::CR4).unwrap();
                }
                _ => unreachable!(),
            },
            _ => {}
        }
    }
    VmxExitResult::IncrementRip
}

fn handle_cpuid(guest_regs: &mut GuestRegisters) -> VmxExitResult {
    let leaf = guest_regs.rax as u32;
    let sub_leaf = guest_regs.rcx as u32;

    let mut result = cpuid!(leaf, sub_leaf);

    if leaf == CpuidLeaf::FeatureInformation as u32 {
        // Hide presence of hypervisor.
        result
            .ecx
            .bitand_assign(!(FeatureBits::HypervisorPresentBit as u32));
    }

    guest_regs.rax = result.eax as u64;
    guest_regs.rbx = result.ebx as u64;
    guest_regs.rcx = result.ecx as u64;
    guest_regs.rdx = result.edx as u64;

    VmxExitResult::IncrementRip
}

#[unsafe(no_mangle)]
pub fn vm_exit_prepare(guest_regs: &mut GuestRegisters) {
    // This is extremely unsafe but only way to get the current HyperProcessor object.
    let status = unsafe { HYPER_RING_STATUS.data_ptr().as_mut().unwrap() };
    let status = unsafe { status.assume_init_mut() };
    let pid = unsafe { KeGetCurrentProcessorNumberEx(null_mut()) };
    let processor = unsafe { status.processors[pid as usize].data_ptr().as_mut().unwrap() };

    unsafe {
        guest_regs.rip = vmread(vmx::vmcs::guest::RIP).unwrap();
        guest_regs.rsp = vmread(vmx::vmcs::guest::RSP).unwrap();
    }

    let result = unsafe { vm_exit_dispatcher(guest_regs, processor) };
    match result {
        VmxExitResult::None => {}
        VmxExitResult::IncrementRip => {
            processor.vmcs.as_mut().unwrap().vm_increment_rip();
        }
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "sysv64" fn vm_exit_handler() {
    // RSP holds pointer to the VmmStack object.
    // [RSP] is pointer to the GuestRegisters.
    // [RSP + 8] is pointer to the real stack to use.
    // RBP is set to original RSP.

    // We add 4096 to RSP before tha call because stack grows downwards.
    // Our allocation points on top (in normal terms, beginning) of the stack.
    // So we have to adjust accordingly.
    naked_asm!(
        "
        mov rbp, rsp
    mov rsp, [rbp]
    mov [rsp], rcx
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], rbx
    mov [rsp + 32], rbp
    mov [rsp + 40], rsi
    mov [rsp + 48], rdi
    mov [rsp + 56], r8
    mov [rsp + 64], r9
    mov [rsp + 72], r10
    mov [rsp + 80], r11
    mov [rsp + 88], r12
    mov [rsp + 96], r13
    mov [rsp + 104], r14
    mov [rsp + 112], r15

    mov rsp, [rbp + 8]
    add rsp, 4096
    mov rcx, [rbp]
    call vm_exit_prepare

    mov rsp, [rbp]
    mov rax, [rsp]
    mov rcx, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rbx, [rsp + 24]
    mov rbp, [rsp + 32]
    mov rsi, [rsp + 40]
    mov rdi, [rsp + 48]
    mov r8, [rsp + 56]
    mov r9, [rsp + 64]
    mov r10, [rsp + 72]
    mov r11, [rsp + 80]
    mov r12, [rsp + 88]
    mov r13, [rsp + 96]
    mov r14, [rsp + 104]
    mov r15, [rsp + 112]

	vmresume
	call vmresume_failed"
    );
}
