extern crate alloc;
use core::mem::MaybeUninit;

use lazy_static::lazy_static;
use spin::lock_api::*;

use crate::intel::vm::hyper_status::HyperRingStatus;
use alloc::boxed::Box;
use core::sync::atomic::AtomicU64;

lazy_static! {
    pub static ref HYPER_RING_STATUS: Mutex<Box<MaybeUninit<HyperRingStatus>>> =
        Mutex::new(Box::new_uninit());
    pub static ref VIRTUALIZATION_BITMAP: AtomicU64 = AtomicU64::new(0);
}
