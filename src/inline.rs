//! Wrapper for inline functions

use crate::*;
use std::mem::{self, MaybeUninit};
use std::os::raw::*;
use std::ptr::{self, addr_of_mut};
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

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
pub unsafe fn rte_mempool_from_obj(obj: *mut c_void) -> *mut rte_mempool {
    let hdr = rte_mempool_get_header(obj);
    (*hdr).mp
}

#[inline]
unsafe fn rte_mempool_get_header(obj: *mut c_void) -> *mut rte_mempool_objhdr {
    (obj as *mut c_uint).sub(mem::size_of::<rte_mempool_objhdr>()) as *mut rte_mempool_objhdr
}

#[inline]
unsafe fn rte_mempool_get_ops(ops_index: c_int) -> *mut rte_mempool_ops {
    if ops_index < 0 || ops_index >= RTE_MEMPOOL_MAX_OPS_IDX as c_int {
        panic!("invalid ops_indx: {ops_index}");
    }
    rte_mempool_ops_table
        .ops
        .as_mut_ptr()
        .add(ops_index as usize)
}

#[inline]
unsafe fn rte_mempool_ops_dequeue_bulk(
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
unsafe fn rte_mempool_ops_enqueue_bulk(
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

#[inline(always)]
unsafe fn rte_mempool_generic_get(
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

#[inline(always)]
pub unsafe fn rte_mempool_generic_put(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: c_uint,
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

#[inline(always)]
pub unsafe fn rte_mempool_get_bulk(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: c_uint,
) -> c_int {
    let cache = rte_mempool_default_cache(mp, rte_lcore_id());
    rte_mempool_generic_get(mp, obj_table, n, cache)
}

#[inline(always)]
pub unsafe fn rte_mempool_put_bulk(mp: *mut rte_mempool, obj_table: *mut *mut c_void, n: c_uint) {
    let cache = rte_mempool_default_cache(mp, rte_lcore_id());
    rte_mempool_generic_put(mp, obj_table, n, cache);
}

#[inline(always)]
pub unsafe fn rte_mempool_get(mp: *mut rte_mempool, obj_p: *mut *mut c_void) -> c_int {
    rte_mempool_get_bulk(mp, obj_p, 1)
}

#[inline(always)]
pub unsafe fn rte_mempool_put(mp: *mut rte_mempool, mut obj: *mut c_void) {
    rte_mempool_put_bulk(mp, addr_of_mut!(obj), 1);
}

#[inline]
pub unsafe fn rte_mempool_default_cache(
    mp: *mut rte_mempool,
    lcore_id: c_uint,
) -> *mut rte_mempool_cache {
    if (*mp).cache_size == 0 {
        return ptr::null_mut();
    }
    if lcore_id > RTE_MAX_LCORE {
        return ptr::null_mut();
    }
    (*mp).local_cache.add(lcore_id as _)
}

#[inline(always)]
pub unsafe fn rte_mempool_cache_flush(mut cache: *mut rte_mempool_cache, mp: *mut rte_mempool) {
    if cache.is_null() {
        cache = rte_mempool_default_cache(mp, rte_lcore_id());
    }
    if cache.is_null() || (*cache).len == 0 {
        return;
    }
    rte_mempool_ops_enqueue_bulk(mp, (*cache).objs.as_mut_ptr(), (*cache).len);
    (*cache).len = 0;
}

#[inline]
pub unsafe fn rte_mbuf_raw_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    let mut m = MaybeUninit::<rte_mbuf>::uninit();
    let mut m = m.as_mut_ptr();
    if rte_mempool_get(mp, addr_of_mut!(m) as *mut *mut c_void) < 0 {
        return ptr::null_mut();
    }
    return m;
}

#[inline(always)]
pub unsafe fn rte_mbuf_raw_free(m: *mut rte_mbuf) {
    assert!((*m).ol_flags & RTE_MBUF_F_INDIRECT == 0);
    assert!(
        (*m).ol_flags & RTE_MBUF_F_EXTERNAL == 0
            || rte_pktmbuf_priv_flags((*m).pool) & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF != 0
    );
    rte_mempool_put((*m).pool, m as *mut c_void);
}

#[inline]
pub unsafe fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    let m = rte_mbuf_raw_alloc(mp);
    if !m.is_null() {
        rte_pktmbuf_reset(m);
    }
    m
}

#[inline]
pub unsafe fn rte_pktmbuf_reset(m: *mut rte_mbuf) {
    (*m).next = ptr::null_mut();
    (*m).pkt_len = 0;
    //(*m).tx_offload = 0;
    (*m).vlan_tci = 0;
    (*m).vlan_tci_outer = 0;
    (*m).nb_segs = 1;
    (*m).port = RTE_MBUF_PORT_INVALID as u16;

    (*m).ol_flags &= RTE_MBUF_F_EXTERNAL;
    //(*m).packet_type = 0;
    rte_pktmbuf_reset_headroom(m);

    (*m).data_len = 0;
}

#[inline]
pub unsafe fn rte_pktmbuf_reset_headroom(m: *mut rte_mbuf) {
    (*m).data_off = (*m).buf_len.min(128);
}

#[inline]
pub unsafe fn rte_pktmbuf_attach(mi: *mut rte_mbuf, m: *mut rte_mbuf) {
    assert!((*mi).ol_flags & (RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL) == 0);
    assert!(rte_mbuf_refcnt_read(mi) == 1);
    if (*m).ol_flags & RTE_MBUF_F_EXTERNAL != 0 {
        let _ = rte_mbuf_ext_refcnt_update((*m).shinfo, 1);
        (*mi).ol_flags = (*m).ol_flags;
        (*mi).shinfo = (*m).shinfo;
    } else {
        let _ = rte_mbuf_refcnt_update(rte_mbuf_from_indirect(m), 1);
        (*mi).priv_size = (*m).priv_size;
        (*mi).ol_flags = (*m).ol_flags | RTE_MBUF_F_INDIRECT;
    }

    __rte_pktmbuf_copy_hdr(mi, m);

    (*mi).data_off = (*m).data_off;
    (*mi).data_len = (*m).data_len;
    (*mi).buf_iova = (*m).buf_iova;
    (*mi).buf_addr = (*m).buf_addr;
    (*mi).buf_len = (*m).buf_len;

    (*mi).next = ptr::null_mut();
    (*mi).pkt_len = (*m).data_len as u32;
    (*mi).nb_segs = 1;
    // sanity check in debug mode
}

#[inline]
pub unsafe fn rte_pktmbuf_detach(m: *mut rte_mbuf) {
    let mp = (*m).pool;
    if (*m).ol_flags & RTE_MBUF_F_EXTERNAL != 0 {
        let flags = rte_pktmbuf_priv_flags(mp);
        if flags & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF != 0 {
            return;
        }
        __rte_pktmbuf_free_extbuf(m);
    } else {
        __rte_pktmbuf_free_direct(m);
    }
    let priv_size = rte_pktmbuf_priv_size(mp);
    let mbuf_size = mem::size_of::<rte_mbuf>() + priv_size as usize;
    let buf_len = rte_pktmbuf_data_room_size(mp);

    (*m).priv_size = priv_size;
    (*m).buf_addr = (m as *mut c_char).add(mbuf_size) as *mut c_void;
    (*m).buf_iova = rte_mempool_virt2iova(m as *mut c_void) as u64 + mbuf_size as u64;
    (*m).buf_len = buf_len;
    rte_pktmbuf_reset_headroom(m);
    (*m).data_len = 0;
    (*m).ol_flags = 0;
}

#[inline]
unsafe fn rte_mbuf_refcnt_read(m: *mut rte_mbuf) -> c_ushort {
    (*m).refcnt
}

#[inline]
unsafe fn rte_mbuf_refcnt_set(m: *mut rte_mbuf, v: c_ushort) {
    (*m).refcnt = v;
}

#[inline]
unsafe fn rte_mbuf_refcnt_update(m: *mut rte_mbuf, v: c_short) -> c_ushort {
    (*m).refcnt += v as c_ushort;
    (*m).refcnt
}

#[inline]
#[allow(dead_code)]
unsafe fn rte_pktmbuf_refcnt_update(mut m: *mut rte_mbuf, v: c_short) {
    loop {
        rte_mbuf_refcnt_update(m, v);
        m = (*m).next;
        if m == ptr::null_mut() {
            break;
        }
    }
}

#[inline]
pub unsafe fn rte_mbuf_from_indirect(mi: *mut rte_mbuf) -> *mut rte_mbuf {
    (*mi)
        .buf_addr
        // XXX: dpdk use size_of_val here...
        .sub(mem::size_of::<rte_mbuf>() + (*mi).priv_size as usize) as *mut rte_mbuf
}

#[inline]
unsafe fn rte_mbuf_ext_refcnt_read(shinfo: *mut rte_mbuf_ext_shared_info) -> c_ushort {
    let refcnt = AtomicU16::from_mut(&mut (*shinfo).refcnt);
    refcnt.load(Ordering::Relaxed)
}

#[inline]
unsafe fn rte_mbuf_ext_refcnt_set(shinfo: *mut rte_mbuf_ext_shared_info, v: c_ushort) {
    let refcnt = AtomicU16::from_mut(&mut (*shinfo).refcnt);
    refcnt.store(v, Ordering::Relaxed);
}

#[inline]
unsafe fn rte_mbuf_ext_refcnt_update(
    shinfo: *mut rte_mbuf_ext_shared_info,
    v: c_short,
) -> c_ushort {
    let mut v = v as c_ushort;
    if rte_mbuf_ext_refcnt_read(shinfo) == 1 {
        v += 1;
        rte_mbuf_ext_refcnt_set(shinfo, v);
        return v;
    }
    let refcnt = AtomicU16::from_mut(&mut (*shinfo).refcnt);
    // XXX: equivalent to gcc __atomic_add_fetch?
    // XXX: nightly feature!
    refcnt.fetch_add(v, Ordering::AcqRel) + v
}

#[inline]
unsafe fn rte_mempool_get_priv(mp: *mut rte_mempool) -> *mut c_void {
    let cache_sz = (*mp).cache_size;
    let mut offset = std::mem::size_of::<rte_mempool>();
    if cache_sz != 0 {
        offset += mem::size_of::<rte_mempool_cache>() * RTE_MAX_LCORE as usize;
    }
    (mp as *mut c_char).add(offset) as *mut c_void
}

#[inline]
unsafe fn rte_mempool_virt2iova(elt: *const c_void) -> rte_iova_t {
    let hdr =
        (elt as *mut c_uint).sub(mem::size_of::<rte_mempool_objhdr>()) as *const rte_mempool_objhdr;
    (*hdr).iova
}

#[inline]
unsafe fn rte_pktmbuf_priv_size(mp: *mut rte_mempool) -> c_ushort {
    let mbp_priv = rte_mempool_get_priv(mp) as *mut rte_pktmbuf_pool_private;
    (*mbp_priv).mbuf_priv_size
}

#[inline]
unsafe fn rte_pktmbuf_priv_flags(mp: *mut rte_mempool) -> c_uint {
    let mbp_priv = rte_mempool_get_priv(mp) as *mut rte_pktmbuf_pool_private;
    (*mbp_priv).flags
}

#[inline]
pub unsafe fn rte_pktmbuf_data_room_size(mp: *mut rte_mempool) -> c_ushort {
    let mbp_priv = rte_mempool_get_priv(mp) as *mut rte_pktmbuf_pool_private;
    (*mbp_priv).mbuf_data_room_size
}

#[inline]
unsafe fn __rte_pktmbuf_copy_hdr(mdst: *mut rte_mbuf, msrc: *mut rte_mbuf) {
    (*mdst).port = (*msrc).port;
    (*mdst).vlan_tci = (*msrc).vlan_tci;
    (*mdst).vlan_tci_outer = (*msrc).vlan_tci_outer;
    // TODO: tx_offload, hash, packet_type
    (*mdst).dynfield1.copy_from_slice(&(*msrc).dynfield1);
}

#[inline]
unsafe fn __rte_pktmbuf_free_extbuf(m: *mut rte_mbuf) {
    assert!((*m).ol_flags & RTE_MBUF_F_EXTERNAL != 0);
    assert!(!(*m).shinfo.is_null());
    if rte_mbuf_ext_refcnt_update((*m).shinfo, -1) == 0 {
        (*(*m).shinfo)
            .free_cb
            .map(|f| f((*m).buf_addr, (*(*m).shinfo).fcb_opaque));
    }
}

#[inline]
unsafe fn __rte_pktmbuf_free_direct(m: *mut rte_mbuf) {
    assert!((*m).ol_flags & RTE_MBUF_F_INDIRECT != 0);
    let md = rte_mbuf_from_indirect(m);
    if rte_mbuf_refcnt_update(md, -1) == 0 {
        (*md).next = ptr::null_mut();
        (*md).nb_segs = 1;
        rte_mbuf_refcnt_set(md, 1);
        rte_mbuf_raw_free(md);
    }
}
