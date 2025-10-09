//TODO: Merge with VmExitInterruptionInformation on vmx_def.rs

use crate::intel::vmx_def::{
    VmxExceptionInterrupt,
    VmxInterruptionType,
};
use bitfields::bitfield;

#[bitfield(u32)]
pub struct VmxEvent {
    #[bits(8)]
    pub vector: VmxExceptionInterrupt,
    #[bits(3)]
    pub event_type: VmxInterruptionType,
    pub deliver_error_code: bool,
    #[bits(19)]
    pub reserved: u64,
    pub is_valid: bool,
}

impl VmxEvent {
    pub fn general_protection_fault() -> Self {
        VmxEventBuilder::new()
            .with_vector(VmxExceptionInterrupt::GeneralProtectionFault)
            .with_event_type(VmxInterruptionType::HardwareException)
            .with_is_valid(true)
            .with_deliver_error_code(true)
            .build()
    }

    pub fn breakpoint() -> Self {
        VmxEventBuilder::new()
            .with_vector(VmxExceptionInterrupt::Breakpoint)
            .with_event_type(VmxInterruptionType::SoftwareException)
            .with_is_valid(true)
            .with_deliver_error_code(false)
            .build()
    }

    pub fn page_fault() -> Self {
        VmxEventBuilder::new()
            .with_vector(VmxExceptionInterrupt::PageFault)
            .with_event_type(VmxInterruptionType::HardwareException)
            .with_is_valid(true)
            .with_deliver_error_code(true)
            .build()
    }

    pub fn undefined_opcode() -> Self {
        VmxEventBuilder::new()
            .with_vector(VmxExceptionInterrupt::InvalidOpcode)
            .with_event_type(VmxInterruptionType::HardwareException)
            .with_is_valid(true)
            .with_deliver_error_code(true)
            .build()
    }
}
