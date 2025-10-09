use wdk_sys::*;

pub unsafe extern "C" fn hr_processor_change_callback(
    callback_context: PVOID,
    change_context: PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT,
    operation_status: PNTSTATUS,
) {
}
