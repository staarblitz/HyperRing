use bitfields::bitfield;
use x86::msr::{
    IA32_VMX_BASIC,
    IA32_VMX_ENTRY_CTLS,
    IA32_VMX_EXIT_CTLS,
    IA32_VMX_PINBASED_CTLS,
    IA32_VMX_PROCBASED_CTLS,
    IA32_VMX_PROCBASED_CTLS2,
    IA32_VMX_TRUE_ENTRY_CTLS,
    IA32_VMX_TRUE_EXIT_CTLS,
    IA32_VMX_TRUE_PINBASED_CTLS,
    IA32_VMX_TRUE_PROCBASED_CTLS,
    rdmsr,
};

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct Msr {
    pub low: u32,
    pub high: u32,
}

#[derive(Clone, Copy)]
pub enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

/// Adjusts the controls according to Intel Software Developer Manual.
pub fn adjust_controls(control: VmxControl, requested_value: u64) -> u64 {
    let vmx_basic = unsafe { rdmsr(IA32_VMX_BASIC) };
    let true_cap_msr_supported = (vmx_basic & 1 << 55) != 0;

    let cap_msr = match (control, true_cap_msr_supported) {
        (VmxControl::PinBased, true) => IA32_VMX_TRUE_PINBASED_CTLS,
        (VmxControl::PinBased, false) => IA32_VMX_PINBASED_CTLS,
        (VmxControl::ProcessorBased, true) => IA32_VMX_TRUE_PROCBASED_CTLS,
        (VmxControl::ProcessorBased, false) => IA32_VMX_PROCBASED_CTLS,
        (VmxControl::VmExit, true) => IA32_VMX_TRUE_EXIT_CTLS,
        (VmxControl::VmExit, false) => IA32_VMX_EXIT_CTLS,
        (VmxControl::VmEntry, true) => IA32_VMX_TRUE_ENTRY_CTLS,
        (VmxControl::VmEntry, false) => IA32_VMX_ENTRY_CTLS,
        (VmxControl::ProcessorBased2, _) => IA32_VMX_PROCBASED_CTLS2,
    };

    let capabilities = unsafe { rdmsr(cap_msr) };
    let allowed0 = capabilities as u32;
    let allowed1 = (capabilities >> 32) as u32;
    let mut effective_value = u32::try_from(requested_value).unwrap();
    effective_value |= allowed0;
    effective_value &= allowed1;
    u64::from(effective_value)
}
