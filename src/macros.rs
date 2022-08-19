//! Some macros definition

/// Rust identification of `RTE_LCORE_FOREACH` macro.
#[macro_export]
macro_rules! lcore_foreach {
    (|$i:ident| $blk:block) => {
        let mut $i = u32::MAX;
        loop {
            $i = unsafe { dpdk_sys::rte_get_next_lcore($i, 0, 0) };
            if $i >= dpdk_sys::RTE_MAX_LCORE {
                break;
            }
            $blk
        }
    };
}

/// Rust identification of `RTE_LCORE_FOREACH_WORKER` macro.
#[macro_export]
macro_rules! lcore_foreach_worker {
    (|$i:ident| $blk:block) => {
        let mut $i = u32::MAX;
        loop {
            $i = unsafe { dpdk_sys::rte_get_next_lcore($i, 1, 0) };
            if $i >= dpdk_sys::RTE_MAX_LCORE {
                break;
            }
            $blk
        }
    };
}

#[macro_export]
macro_rules! eth_foreach_dev {
    (|$p:ident| $blk:block) => {
        let mut $p = u32::MAX;
        loop {
            $p = unsafe {
                dpdk_sys::rte_eth_find_next_owned_by($p + 1, dpdk_sys::RTE_ETH_DEV_NO_OWNER)
            };
            if $i >= dpdk_sys::RTE_MAX_ETHPORTS {
                break;
            }
            $blk
        }
    };
}

#[macro_export]
macro_rules! cstring {
    ($s:expr) => {
        std::ffi::CString::new($s).unwrap().as_ptr()
    };
}

#[macro_export]
macro_rules! errno {
    () => {
        dpdk_sys::thread_local::per_lcore__rte_errno
    };
}
