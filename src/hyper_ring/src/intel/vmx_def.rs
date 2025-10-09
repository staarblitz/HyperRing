extern crate alloc;
use bitfields::bitfield;
use core::arch::naked_asm;
use wdk_sys::CONTEXT;
use x86::{
    current::vmx::vmread,
    vmx::VmFail,
};

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct EPTP {
    #[bits(3)]
    pub memory_type: u64,

    #[bits(3)]
    pub page_walk_length: u64,

    #[bits(1)]
    pub dirty_and_access_enabled: bool,

    #[bits(5)]
    pub reserved: u64,

    #[bits(36)]
    pub pml4_address: u64,

    #[bits(16)]
    pub reserved2: u64,
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct EPTPML4E {
    #[bits(1)]
    pub read: bool,
    #[bits(1)]
    pub write: bool,
    #[bits(1)]
    pub execute: bool,
    #[bits(5)]
    pub reserved: u64,
    #[bits(1)]
    pub accessed: bool,
    #[bits(1)]
    pub ignored: u64,
    #[bits(1)]
    pub execute_for_user_mode: bool,
    #[bits(1)]
    pub ignored2: u64,
    #[bits(36)]
    pub physical_address: u64,
    #[bits(4)]
    pub reserved2: u64,
    #[bits(12)]
    pub ignored3: u64,
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct EPTPDPTE {
    #[bits(1)]
    pub read: bool,
    #[bits(1)]
    pub write: bool,
    #[bits(1)]
    pub execute: bool,
    #[bits(5)]
    pub reserved: u64,
    #[bits(1)]
    pub accessed: bool,
    #[bits(1)]
    pub ignored: u64,
    #[bits(1)]
    pub execute_for_user_mode: bool,
    #[bits(1)]
    pub ignored2: u64,
    #[bits(36)]
    pub physical_address: u64,
    #[bits(4)]
    pub reserved2: u64,
    #[bits(12)]
    pub ignored3: u64,
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct EPTPDE {
    #[bits(1)]
    pub read: bool,
    #[bits(1)]
    pub write: bool,
    #[bits(1)]
    pub execute: bool,
    #[bits(5)]
    pub reserved: u64,
    #[bits(1)]
    pub accessed: bool,
    #[bits(1)]
    pub ignored: u64,
    #[bits(1)]
    pub execute_for_user_mode: bool,
    #[bits(1)]
    pub ignored2: u64,
    #[bits(36)]
    pub physical_address: u64,
    #[bits(4)]
    pub reserved2: u64,
    #[bits(12)]
    pub ignored3: u64,
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct EPTPTE {
    #[bits(1)]
    pub read: bool,
    #[bits(1)]
    pub write: bool,
    #[bits(1)]
    pub execute: bool,
    #[bits(3)]
    pub ept_memory_type: u64,
    #[bits(1)]
    pub ignore_pat: bool,
    #[bits(1)]
    pub ignored: bool,
    #[bits(1)]
    pub accessed: bool,
    #[bits(1)]
    pub dirty: bool,
    #[bits(1)]
    pub execute_for_user_mode: bool,
    #[bits(1)]
    pub ignored2: u64,
    #[bits(36)]
    pub physical_address: u64,
    #[bits(4)]
    pub reserved2: u64,
    #[bits(11)]
    pub ignored3: u64,
    #[bits(1)]
    pub suppress_ve: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FeatureBits {
    HypervisorVmxSupportBit = 5,
    HypervisorPresentBit = 31,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
/// Enum representing the various CPUID leaves for feature and interface discovery.
/// Reference: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
pub enum CpuidLeaf {
    /// CPUID function number to retrieve the processor's vendor identification string.
    VendorInfo = 0x0,

    /// CPUID function for feature information, including hypervisor presence.
    FeatureInformation = 0x1,

    /// CPUID function for cache information.
    CacheInformation = 0x2,

    /// CPUID function for extended feature information.
    ExtendedFeatureInformation = 0x7,

    /// Hypervisor vendor information leaf.
    HypervisorVendor = 0x40000000,

    /// Hypervisor interface identification leaf.
    HypervisorInterface = 0x40000001,

    /// Hypervisor system identity information leaf.
    HypervisorSystemIdentity = 0x40000002,

    /// Hypervisor feature identification leaf.
    HypervisorFeatureIdentification = 0x40000003,

    /// Hypervisor implementation recommendations leaf.
    ImplementationRecommendations = 0x40000004,

    /// Hypervisor implementation limits leaf.
    HypervisorImplementationLimits = 0x40000005,

    /// Hardware-specific features in use by the hypervisor leaf.
    ImplementationHardwareFeatures = 0x40000006,

    /// Nested hypervisor feature identification leaf.
    NestedHypervisorFeatureIdentification = 0x40000009,

    /// Nested virtualization features available leaf.
    HypervisorNestedVirtualizationFeatures = 0x4000000A,
}

#[derive(PartialEq, Eq)]
#[repr(u8)]
pub enum VmxMovCrAccessType {
    MovToCr = 0,
    MovFromCr = 1,
    Clts = 2,
    Lmsw = 3,
}

impl VmxMovCrAccessType {
    const fn into_bits(self) -> u8 {
        self as _
    }

    const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::MovToCr,
            1 => Self::MovFromCr,
            2 => Self::Clts,
            3 => Self::Lmsw,
            _ => unreachable!(),
        }
    }
}

#[bitfield(u64)]
#[derive(Copy, Clone)]
pub struct VmxMovCrExitQualification {
    #[bits(4)]
    pub control_register: u32,

    #[bits(2)]
    pub access_type: VmxMovCrAccessType,

    #[bits(1)]
    pub operand_type: u8,

    #[bits(1)]
    pub reserved: u8,

    #[bits(4)]
    pub register: u32,

    #[bits(16)]
    pub source_data: u16,

    #[bits(36)]
    __: u64,
}

#[derive(Debug)]
pub struct HyperFail {
    pub failure_const: u64,
}

impl HyperFail {
    pub fn from_vm_fail(fail: VmFail) -> Result<(), HyperFail> {
        match fail {
            VmFail::VmFailInvalid => Err(HyperFail { failure_const: 0 }),
            VmFail::VmFailValid => unsafe {
                Err(HyperFail {
                    failure_const: vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR).unwrap(),
                })
            },
        }
    }

    pub fn from_nt_fail(fail: i32) -> Result<(), HyperFail> {
        Err(HyperFail {
            failure_const: fail as u64,
        })
    }
}
#[repr(C, align(16))]
#[derive(Copy, Clone, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub rflags: u64,
    pub rsp: u64,
    pub rip: u64,
}

impl GuestRegisters {
    pub fn from_context(context: &CONTEXT) -> Self {
        Self {
            rax: context.Rax,
            rcx: context.Rcx,
            rdx: context.Rdx,
            rbx: context.Rbx,
            rbp: context.Rbp,
            rsi: context.Rsi,
            rdi: context.Rdi,
            r8: context.R8,
            r9: context.R9,
            r10: context.R10,
            r11: context.R11,
            r12: context.R12,
            r13: context.R13,
            r14: context.R14,
            r15: context.R15,
            rflags: context.EFlags as u64,
            rsp: context.Rsp,
            rip: context.Rip,
        }
    }
    #[unsafe(naked)]
    pub extern "sysv64" fn capture(&self) {
        naked_asm!(
            "
            mov [rcx], rax
mov [rcx + 8], rcx
mov [rcx + 16], rdx
mov [rcx + 24], rbx
mov [rcx + 32], rbp
mov [rcx + 40], rsi
mov [rcx + 48], rdi
mov [rcx + 56], r8
mov [rcx + 64], r9
mov [rcx + 72], r10
mov [rcx + 80], r11
mov [rcx + 88], r12
mov [rcx + 96], r13
mov [rcx + 104], r14
mov [rcx + 112], r15

pushfq
pop rax
mov [rcx + 120], rax

mov rax, rsp
add rax, 8
mov [rcx + 128], rax

mov rax, [rsp]
add rax, 8
mov [rcx + 136], rax

ret"
        )
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum VmxInterruptionType {
    #[default]
    ExternalInterrupt = 0,
    Reserved = 1,
    NonMaskableInterrupt = 2,
    HardwareException = 3,
    SoftwareInterrupt = 4,
    PrivilegedSoftwareException = 5,
    SoftwareException = 6,
    OtherEvent = 7,
}

impl VmxInterruptionType {
    pub const fn into_bits(self) -> u8 {
        self as _
    }
    pub const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::ExternalInterrupt,
            1 => Self::Reserved,
            2 => Self::NonMaskableInterrupt,
            3 => Self::HardwareException,
            4 => Self::SoftwareInterrupt,
            5 => Self::PrivilegedSoftwareException,
            6 => Self::SoftwareException,
            _ => Self::OtherEvent,
        }
    }
}

#[derive(Default, Copy, Clone)]
pub struct VmExitInterruptionInformation {
    pub vector: u8,
    pub interruption_type: VmxInterruptionType,
    pub error_code_valid: bool,
    pub nmi_unblocking_due_to_iret: bool,
    pub valid: bool,
}

impl VmExitInterruptionInformation {
    pub fn from_u32(value: u32) -> Self {
        let vector = (value & 0xff) as u8;
        let interruption_type_bits = ((value >> 8) & 0x7) as u8;
        let interruption_type = VmxInterruptionType::from_bits(interruption_type_bits);

        Self {
            vector,
            interruption_type,
            error_code_valid: (value & (1 << 11)) != 0,
            nmi_unblocking_due_to_iret: (value & (1 << 12)) != 0,
            valid: (value & (1 << 31)) != 0,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmxExceptionInterrupt {
    DivisionError = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTSS = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    FloatingPointError = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SimdFloatingPointException = 19,
    VirtualizationException = 20,
    ControlProtectionException = 21,
    MaskableInterrupts = 32,
}

impl VmxExceptionInterrupt {
    pub const fn into_bits(self) -> u32 {
        self as _
    }
    pub const fn from_bits(value: u32) -> Self {
        match value {
            0 => Self::DivisionError,
            1 => Self::Debug,
            2 => Self::NonMaskableInterrupt,
            3 => Self::Breakpoint,
            4 => Self::Overflow,
            5 => Self::BoundRangeExceeded,
            6 => Self::InvalidOpcode,
            7 => Self::DeviceNotAvailable,
            8 => Self::DoubleFault,
            9 => Self::CoprocessorSegmentOverrun,
            10 => Self::InvalidTSS,
            11 => Self::SegmentNotPresent,
            12 => Self::StackSegmentFault,
            13 => Self::GeneralProtectionFault,
            14 => Self::PageFault,
            16 => Self::FloatingPointError,
            17 => Self::AlignmentCheck,
            18 => Self::MachineCheck,
            19 => Self::SimdFloatingPointException,
            20 => Self::VirtualizationException,
            21 => Self::ControlProtectionException,
            32 => Self::MaskableInterrupts,
            _ => Self::DivisionError,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmxExitResult {
    None = 0,
    IncrementRip = 1,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmxExitReason {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSystemManagementInterrupt = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    ControlRegisterAccesses = 28,
    MovDr = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheckEvent = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    AccessToGdtrOrIdtr = 46,
    AccessToLdtrOrTr = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    VmxPreemptionTimerExpired = 52,
    Invvpid = 53,
    WbinvdOrWbnoinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    PageModificationLogFull = 62,
    Xsaves = 63,
    Xrstors = 64,
    Pconfig = 65,
    SppRelatedEvent = 66,
    Umwait = 67,
    Tpause = 68,
    Loadiwkey = 69,
    Enclv = 70,
    EnqcmdPasidTranslationFailure = 72,
    EnqcmdsPasidTranslationFailure = 73,
    BusLock = 74,
    InstructionTimeout = 75,
}

impl VmxExitReason {
    pub fn from_u32(value: u32) -> Option<Self> {
        let basic_exit_reason = (value & 0xFFFF) as u16;
        match basic_exit_reason {
            0 => Some(Self::ExceptionOrNmi),
            1 => Some(Self::ExternalInterrupt),
            2 => Some(Self::TripleFault),
            3 => Some(Self::InitSignal),
            4 => Some(Self::StartupIpi),
            5 => Some(Self::IoSystemManagementInterrupt),
            6 => Some(Self::OtherSmi),
            7 => Some(Self::InterruptWindow),
            8 => Some(Self::NmiWindow),
            9 => Some(Self::TaskSwitch),
            10 => Some(Self::Cpuid),
            11 => Some(Self::Getsec),
            12 => Some(Self::Hlt),
            13 => Some(Self::Invd),
            14 => Some(Self::Invlpg),
            15 => Some(Self::Rdpmc),
            16 => Some(Self::Rdtsc),
            17 => Some(Self::Rsm),
            18 => Some(Self::Vmcall),
            19 => Some(Self::Vmclear),
            20 => Some(Self::Vmlaunch),
            21 => Some(Self::Vmptrld),
            22 => Some(Self::Vmptrst),
            23 => Some(Self::Vmread),
            24 => Some(Self::Vmresume),
            25 => Some(Self::Vmwrite),
            26 => Some(Self::Vmxoff),
            27 => Some(Self::Vmxon),
            28 => Some(Self::ControlRegisterAccesses),
            29 => Some(Self::MovDr),
            30 => Some(Self::IoInstruction),
            31 => Some(Self::Rdmsr),
            32 => Some(Self::Wrmsr),
            33 => Some(Self::VmEntryFailureInvalidGuestState),
            34 => Some(Self::VmEntryFailureMsrLoading),
            36 => Some(Self::Mwait),
            37 => Some(Self::MonitorTrapFlag),
            39 => Some(Self::Monitor),
            40 => Some(Self::Pause),
            41 => Some(Self::VmEntryFailureMachineCheckEvent),
            43 => Some(Self::TprBelowThreshold),
            44 => Some(Self::ApicAccess),
            45 => Some(Self::VirtualizedEoi),
            46 => Some(Self::AccessToGdtrOrIdtr),
            47 => Some(Self::AccessToLdtrOrTr),
            48 => Some(Self::EptViolation),
            49 => Some(Self::EptMisconfiguration),
            50 => Some(Self::Invept),
            51 => Some(Self::Rdtscp),
            52 => Some(Self::VmxPreemptionTimerExpired),
            53 => Some(Self::Invvpid),
            54 => Some(Self::WbinvdOrWbnoinvd),
            55 => Some(Self::Xsetbv),
            56 => Some(Self::ApicWrite),
            57 => Some(Self::Rdrand),
            58 => Some(Self::Invpcid),
            59 => Some(Self::Vmfunc),
            60 => Some(Self::Encls),
            61 => Some(Self::Rdseed),
            62 => Some(Self::PageModificationLogFull),
            63 => Some(Self::Xsaves),
            64 => Some(Self::Xrstors),
            65 => Some(Self::Pconfig),
            66 => Some(Self::SppRelatedEvent),
            67 => Some(Self::Umwait),
            68 => Some(Self::Tpause),
            69 => Some(Self::Loadiwkey),
            70 => Some(Self::Enclv),
            72 => Some(Self::EnqcmdPasidTranslationFailure),
            73 => Some(Self::EnqcmdsPasidTranslationFailure),
            74 => Some(Self::BusLock),
            75 => Some(Self::InstructionTimeout),
            _ => None,
        }
    }
}
