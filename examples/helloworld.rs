use std::{
    env,
    ffi::{c_void, CString},
    os::raw::c_char,
    ptr,
};

use dpdk_sys::{rte_eal_remote_launch, rte_get_next_lcore, RTE_MAX_LCORE};

unsafe extern "C" fn lcore_main(_args: *mut c_void) -> i32 {
    println!("hello from lcore");
    0
}

fn main() {
    // Parse arguments.
    let args = env::args().collect::<Vec<_>>();
    let args = args
        .into_iter()
        .map(|a| CString::new(a).unwrap())
        .collect::<Vec<_>>();
    let mut p_args = args
        .iter()
        .map(|cstr| cstr.as_ptr() as *mut c_char)
        .collect::<Vec<_>>();

    // Initialization of Environment Abstract Layer (EAL).
    let ret = unsafe { dpdk_sys::rte_eal_init(0, p_args.as_mut_ptr()) };
    if ret < 0 {
        let msg = CString::new("cannot init EAL").unwrap();
        unsafe { dpdk_sys::rte_exit(ret, msg.as_ptr()) };
    }

    // Launches the function on each lcore.
    let mut lcore_id = u32::MAX;
    loop {
        lcore_id = unsafe { rte_get_next_lcore(lcore_id, 1, 0) };
        if lcore_id >= RTE_MAX_LCORE {
            break;
        }
        unsafe {
            rte_eal_remote_launch(Some(lcore_main), ptr::null_mut() as *mut c_void, lcore_id)
        };
    }

    // Call it on main lcore too.
    unsafe { lcore_main(ptr::null_mut() as *mut c_void) };

    unsafe { dpdk_sys::rte_eal_mp_wait_lcore() };

    // Clean up EAL.
    unsafe { dpdk_sys::rte_eal_cleanup() };
}
