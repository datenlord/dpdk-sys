//! DPDK-defined thread-local variables

extern "C" {
    #[thread_local]
    pub static mut per_lcore__lcore_id: ::std::os::raw::c_uint;
    #[thread_local]
    pub static mut per_lcore__thread_id: ::std::os::raw::c_int;
    #[thread_local]
    pub static mut per_lcore__rte_errno: ::std::os::raw::c_int;
    #[thread_local]
    pub static mut per_lcore_trace_mem: *mut ::std::os::raw::c_void;
    #[thread_local]
    pub static mut per_lcore_trace_point_sz: ::std::os::raw::c_int;
}
