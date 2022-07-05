//! DPDK-defined thread-local variables
use std::os::raw::*;

extern "C" {
    #[thread_local]
    pub static mut per_lcore__lcore_id: c_uint;
    #[thread_local]
    pub static mut per_lcore__thread_id: c_int;
    #[thread_local]
    pub static mut per_lcore__rte_errno: c_int;
    #[thread_local]
    pub static mut per_lcore_trace_mem: *mut c_void;
    #[thread_local]
    pub static mut per_lcore_trace_point_sz: c_int;
}
