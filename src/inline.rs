//! Wrapper for inline functions
use crate::*;

#[inline]
pub unsafe fn rte_lcore_id() -> ::std::os::raw::c_uint {
    thread_local::per_lcore__lcore_id
}

#[inline]
pub unsafe fn rte_gettid() -> ::std::os::raw::c_int {
    if thread_local::per_lcore__thread_id == -1 {
        thread_local::per_lcore__thread_id = rte_sys_gettid();
    }
    thread_local::per_lcore__thread_id
}
