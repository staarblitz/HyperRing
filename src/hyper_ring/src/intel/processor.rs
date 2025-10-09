use wdk::println;
use wdk_sys::{
    DISPATCH_LEVEL,
    KIRQL,
    ntddk::{
        KeGetCurrentIrql,
        KeLowerIrql,
        KeRevertToUserAffinityThread,
        KeSetSystemAffinityThreadEx,
        KfRaiseIrql,
    },
};

#[derive(Clone, Default)]
pub struct ProcessorContext {
    pub id: u32,
    pub irql: KIRQL,
    pub raised: bool,
}

impl ProcessorContext {
    /// Switches to specified processor.
    pub fn switch_to_processor(id: u32) -> ProcessorContext {
        println!("[PCTX] Begin processor context {}", id);
        println!("[PCTX] Switching to processor {}", id);
        unsafe { KeSetSystemAffinityThreadEx(1 << id) };
        ProcessorContext {
            id,
            irql: unsafe { KeGetCurrentIrql() },
            raised: false,
        }
    }

    /// Switches to specified processor and raises to DISPATCH_LEVEL.
    pub fn switch_to_processor_and_raise(id: u32) -> ProcessorContext {
        println!("[PCTX] Begin processor context {}", id);
        let mut irql: KIRQL = 0;
        unsafe {
            println!("[PCTX] Switching to processor {}", id);
            KeSetSystemAffinityThreadEx(1 << id);
            println!("[PCTX] Raising IRQL {}", DISPATCH_LEVEL);
            irql = KfRaiseIrql(DISPATCH_LEVEL as KIRQL);
        };
        ProcessorContext {
            id,
            irql,
            raised: true,
        }
    }
}

impl Drop for ProcessorContext {
    /// Reverts the affinity to default after going out of scope.
    fn drop(&mut self) {
        println!("[PCTX] End processor context {}", self.id);
        unsafe { KeRevertToUserAffinityThread() }
        if self.raised {
            println!("[PCTX] Lowering IRQL {}", self.irql);
            unsafe { KeLowerIrql(self.irql) };
        }
    }
}
