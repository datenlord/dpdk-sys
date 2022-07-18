//! Wrapper for inline functions
use crate::*;
use std::os::raw::*;

#[inline]
pub unsafe fn rte_lcore_id() -> c_uint {
    thread_local::per_lcore__lcore_id
}

#[inline]
pub unsafe fn rte_gettid() -> c_int {
    if thread_local::per_lcore__thread_id == -1 {
        thread_local::per_lcore__thread_id = rte_sys_gettid();
    }
    thread_local::per_lcore__thread_id
}

#[inline]
pub unsafe fn rte_mempool_get_ops(ops_index: c_int) -> *mut rte_mempool_ops {
    if ops_index < 0 || ops_index >= RTE_MEMPOOL_MAX_OPS_IDX as c_int {
        panic!("invalid ops_indx: {ops_index}");
    }
    rte_mempool_ops_table
        .ops
        .as_mut_ptr()
        .add(ops_index as usize)
}

#[inline]
pub unsafe fn rte_mempool_ops_dequeue_bulk(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: u32,
) -> c_int {
    let ops = rte_mempool_get_ops((*mp).ops_index);
    if let Some(dequeue) = (*ops).dequeue {
        dequeue(mp, obj_table, n)
    } else {
        -1 // TODO
    }
}

#[inline]
pub unsafe fn rte_mempool_ops_enqueue_bulk(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: u32,
) -> c_int {
    let ops = rte_mempool_get_ops((*mp).ops_index);
    if let Some(enqueue) = (*ops).dequeue {
        enqueue(mp, obj_table, n)
    } else {
        -1 // TODO
    }
}

#[inline]
pub unsafe fn rte_mempool_generic_get(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: u32,
    cache: *mut rte_mempool_cache,
) -> c_int {
    if !cache.is_null() && (*cache).size > n {
        // can be satisfied from cache.
        let cache_objs = (*cache).objs;
        if (*cache).len < n {
            let req = n + ((*cache).size - (*cache).len);
            let errno = rte_mempool_ops_dequeue_bulk(
                mp,
                (*cache).objs[..(*cache).len as _].as_mut_ptr(),
                req,
            );
            if errno < 0 {
                // ring dequeue
                return rte_mempool_ops_dequeue_bulk(mp, obj_table, n);
            }
            (*cache).len += req;
        }
        cache_objs.as_ptr().copy_to(obj_table, n as _);
        (*cache).len -= n;
        return 0;
    }
    // ring_dequeue
    rte_mempool_ops_dequeue_bulk(mp, obj_table, n)
}

#[inline]
pub unsafe fn rte_mempool_generic_put(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: u32,
    cache: *mut rte_mempool_cache,
) {
    if !cache.is_null() && n <= RTE_MEMPOOL_CACHE_MAX_SIZE {
        // can be satisfied from cache.
        let cache_objs = (*cache).objs.as_mut_ptr().add((*cache).len as _);
        cache_objs.copy_to(obj_table, n as _);
        (*cache).len += n;
        if (*cache).len >= (*cache).flushthresh {
            rte_mempool_ops_enqueue_bulk(
                mp,
                (*cache).objs.as_mut_ptr().add((*cache).size as _),
                (*cache).len - (*cache).size,
            );
            (*cache).len = (*cache).size;
        }
    } else {
        // ring_enqueue
        rte_mempool_ops_enqueue_bulk(mp, obj_table, n);
    }
}
