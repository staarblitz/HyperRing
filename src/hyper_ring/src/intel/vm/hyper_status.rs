use crate::intel::{
    processor::ProcessorContext,
    vm::hyper_processor::HyperProcessor,
    vmcs::VmxCtrl,
    vmx_def::{
        EPTP,
        EPTPDE,
        EPTPDPTE,
        EPTPML4E,
        EPTPTE,
        HyperFail,
    },
    vmxon::VmxOnData,
};
use alloc::boxed::Box;
use core::ffi::c_void;
use spin::lock_api::Mutex;
use wdk::println;
use wdk_sys::{
    POOL_FLAG_NON_PAGED,
    UINT64,
    ntddk::{
        ExAllocatePool2,
        KeQueryActiveProcessorCount,
        MmGetPhysicalAddress,
        RtlCaptureContext,
    },
};

#[derive(Default)]
pub struct HyperRingStatus {
    pub processor_count: u32,
    pub processors: [Mutex<HyperProcessor>; 32],
    pub eptp_address: Mutex<Box<EPTP>>,
    pub vmxon: Option<Box<VmxOnData>>,
}

impl HyperRingStatus {
    /// Initializes the instance of global hypervisor status.
    pub fn new() -> Box<HyperRingStatus> {
        unsafe {
            let mut status = Box::new(HyperRingStatus::default());
            status.eptp_address = Mutex::new(Box::new(EPTP::default()));
            status.processor_count = KeQueryActiveProcessorCount(core::ptr::null_mut::<UINT64>());

            // Intel manual states that the hypervisor needs one VMXON region to use within all cores.
            let vmxon = VmxOnData::setup();
            if let Err(err) = vmxon {
                println!("[HP] Failed to setup vmxon {}", err.failure_const);
                panic!();
            }

            status.vmxon = Some(Box::new(vmxon.unwrap()));
            status
        }
    }

    /// Devirtualizes the system and frees allocated resources.
    /// TODO: Actually finish this.
    pub fn deinit(&mut self) {
        let mut i = 0;
        for vp_lock in &mut self.processors {
            if i >= self.processor_count {
                break;
            }

            let mut vp = vp_lock.lock();

            vp.terminate();
            i += 1;
        }
    }

    /// Allocates EPT for the guest.
    /// TODO: Not yet done, nor in use.
    fn init_mem(&mut self) -> Result<(), HyperFail> {
        unsafe {
            let mut alloc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096, 0x2009);
            let pml4 = &mut *(alloc as *mut EPTPML4E);

            alloc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096, 0x2009);
            let pdpte = &mut *(alloc as *mut EPTPDPTE);

            alloc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096, 0x2009);
            let pde = &mut *(alloc as *mut EPTPDE);

            alloc = ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096, 0x2009);
            let mut pte = alloc as *mut EPTPTE;

            for i in 0..9 {
                let fields = pte.as_mut().unwrap();

                fields.set_accessed(false);
                fields.set_dirty(false);
                fields.set_ept_memory_type(6);
                fields.set_execute(true);
                fields.set_execute_for_user_mode(false);
                fields.set_ignore_pat(true);
                fields.set_physical_address(
                    MmGetPhysicalAddress((0 + (i * 4096)) as *mut c_void).QuadPart as u64 / 4096,
                );
                fields.set_read(true);
                fields.set_suppress_ve(false);
                fields.set_write(true);

                pte = pte.add(1);
            }

            pde.set_accessed(true);
            pde.set_execute(true);
            pde.set_execute_for_user_mode(false);
            pde.set_ignored(0);
            pde.set_ignored2(0);
            pde.set_ignored3(0);
            pde.set_physical_address(
                MmGetPhysicalAddress((pte as u64) as *mut c_void).QuadPart as u64 / 4096,
            );
            pde.set_read(true);
            pde.set_reserved(0);
            pde.set_reserved2(0);
            pde.set_write(true);

            pdpte.set_accessed(false);
            pdpte.set_execute(true);
            pdpte.set_execute_for_user_mode(false);
            pdpte.set_ignored(0);
            pdpte.set_ignored2(0);
            pdpte.set_ignored3(0);
            pdpte.set_physical_address(
                MmGetPhysicalAddress((pde as *mut EPTPDE as u64) as *mut c_void).QuadPart as u64
                    / 4096,
            );
            pdpte.set_read(true);
            pdpte.set_reserved(0);
            pdpte.set_reserved2(0);
            pdpte.set_write(true);

            pml4.set_accessed(false);
            pml4.set_execute(true);
            pml4.set_execute_for_user_mode(false);
            pml4.set_ignored(0);
            pml4.set_ignored2(0);
            pml4.set_ignored3(0);
            pml4.set_physical_address(
                MmGetPhysicalAddress((pdpte as *mut EPTPDPTE as u64) as *mut c_void).QuadPart
                    as u64
                    / 4096,
            );
            pml4.set_read(true);
            pml4.set_reserved(0);
            pml4.set_reserved2(0);
            pml4.set_write(true);

            let mut eptp_lock = self.eptp_address.lock();
            let eptp = eptp_lock.as_mut();
            eptp.set_dirty_and_access_enabled(true);
            eptp.set_memory_type(6);
            eptp.set_page_walk_length(4);
            eptp.set_pml4_address(
                MmGetPhysicalAddress((pml4 as *mut EPTPML4E as u64) as *mut c_void).QuadPart as u64
                    / 4096,
            );
            eptp.set_reserved(0);
            eptp.set_reserved2(0);

            Ok(())
        }
    }

    /// Virtualizes all cores on the system.
    pub fn virtualize_system(&mut self) -> Result<(), HyperFail> {
        println!("[HR] Begin virtualizing system.");

        let mut i = 0;
        for processor in &mut self.processors {
            if i >= self.processor_count {
                break;
            }

            println!("[HR] Virtualizing processor {}", i);

            let mut vp = processor.lock();

            println!("[HR] Switching to processor {}", i);
            let _ctx = ProcessorContext::switch_to_processor_and_raise(vp.id);

            println!("[HR] Initializing VMXON for processor {}", i);
            let mut result = self.vmxon.as_mut().unwrap().as_mut().on();
            if let Err(err) = result {
                println!(
                    "[HR] Failed to prepare processor {} due to {}",
                    i, err.failure_const
                );
                return Err(err);
            }

            println!("[HR] Initializing processor {}", i);
            result = vp.init();
            if let Err(err) = result {
                println!(
                    "[HR] Failed to initialize processor {} due to {}",
                    i, err.failure_const
                );
                return Err(err);
            }

            println!("[HR] Capturing context");

            // Get the current context as we will setup our guest according to it.
            vp.guest_regs = Some(unsafe { Box::new_zeroed().assume_init() });
            unsafe { RtlCaptureContext(vp.guest_regs.as_mut().unwrap().as_mut()) };

            println!(
                "[HR] Context RSP {:x} RIP {:x}",
                vp.guest_regs.as_ref().unwrap().Rsp,
                vp.guest_regs.as_ref().unwrap().Rip
            );

            // Check if current core is virtualized.
            // This step is crucial because after a vmlaunch, we are rewinded to the stack (right after RtlCaptureContext above).
            // We cannot virtualize the same core twice.
            if vp.is_virtualized() {
                println!("[HR] Processor {} already virtualized", i);
                i += 1;
                drop(_ctx);
                continue;
            }

            println!("[HR] Launching processor {}", i);
            result = vp.launch();
            if result.is_err() {
                return result;
            }

            println!("[HR] End virtualizing processor {}", i);

            i += 1;
        }

        println!("[HR] End virtualizing system.");
        Ok(())
    }

    /// Initializes all processors on the system.
    pub fn init(&mut self) -> Result<(), HyperFail> {
        println!("[HR] Begin init processors: {}", self.processor_count);
        let mut i = 0;
        for vp_lock in &mut self.processors {
            if i >= self.processor_count {
                break;
            }

            println!("[HR] Begin init processor: {}", i);

            let mut vp = vp_lock.lock();

            println!("[HP] Initializing VMCS");
            let vmcs = VmxCtrl::setup();
            if let Err(err) = vmcs {
                println!("[HP] Failure initializing VMCS");
                return Err(err);
            }

            vp.id = i;
            vp.vmcs = Some(Box::new(vmcs?));

            println!("[HR] End init processor: {}", i);

            i += 1;
        }
        println!("[HR] End init processors.");
        Ok(())
    }
}
