//! Wrapper for inline functions

use crate::*;
use std::arch::asm;
use std::mem::{self, MaybeUninit};
use std::os::raw::*;
use std::ptr::{self, addr_of_mut};
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

#[inline]
pub unsafe fn rte_mempool_from_obj(obj: *mut c_void) -> *mut rte_mempool {
    let hdr = rte_mempool_get_header(obj);
    (*hdr).mp
}

#[inline]
unsafe fn rte_mempool_get_header(obj: *mut c_void) -> *mut rte_mempool_objhdr {
    (obj as *mut c_char).sub(mem::size_of::<rte_mempool_objhdr>()) as *mut rte_mempool_objhdr
}

#[inline]
unsafe fn rte_mempool_get_ops(ops_index: c_int) -> *mut rte_mempool_ops {
    assert!(ops_index >= 0);
    assert!(ops_index < RTE_MEMPOOL_MAX_OPS_IDX as c_int);
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
        -libc::ENOTSUP
    }
}

#[inline]
unsafe fn rte_mempool_ops_enqueue_bulk(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: u32,
) -> c_int {
    let ops = rte_mempool_get_ops((*mp).ops_index);
    if let Some(enqueue) = (*ops).enqueue {
        enqueue(mp, obj_table, n)
    } else {
        -libc::ENOTSUP
    }
}

#[inline(always)]
unsafe fn rte_mempool_generic_get(
    mp: *mut rte_mempool,
    mut obj_table: *mut *mut c_void,
    n: u32,
    cache: *mut rte_mempool_cache,
) -> c_int {
    if !cache.is_null() && (*cache).size > n {
        // can be satisfied from cache.
        let cache_objs = (*cache).objs.as_ptr();
        if (*cache).len < n {
            // backfill the cache first, then fill n from it.
            let req = n + ((*cache).size - (*cache).len);
            let errno = rte_mempool_ops_dequeue_bulk(
                mp,
                (*cache).objs.as_mut_ptr().add((*cache).len as _),
                req,
            );
            if errno < 0 {
                // ring dequeue:
                return rte_mempool_ops_dequeue_bulk(mp, obj_table, n);
            }
            (*cache).len += req;
        }
        // fill obj_table from cache.
        let mut len = ((*cache).len - 1) as usize;
        for _ in 0..n {
            obj_table.copy_from(cache_objs.add(len), 1);
            obj_table = obj_table.add(1);
            len -= 1;
        }
        (*cache).len -= n;
        return 0;
    }
    // ring_dequeue:
    rte_mempool_ops_dequeue_bulk(mp, obj_table, n)
}

#[inline(always)]
pub unsafe fn rte_mempool_generic_put(
    mp: *mut rte_mempool,
    obj_table: *mut *mut c_void,
    n: c_uint,
    cache: *mut rte_mempool_cache,
) {
    rte_mempool_check_cookies(mp, obj_table, n, 0);
    if !cache.is_null() && n <= RTE_MEMPOOL_CACHE_MAX_SIZE {
        // can be satisfied from cache.
        let cache_objs = (*cache).objs.as_mut_ptr().add((*cache).len as _);
        obj_table.copy_to(cache_objs, n as _);
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
    let cache = rte_mempool_default_cache(mp, rte_lcore_id_stub());
    rte_mempool_generic_get(mp, obj_table, n, cache)
}

#[inline(always)]
pub unsafe fn rte_mempool_put_bulk(mp: *mut rte_mempool, obj_table: *mut *mut c_void, n: c_uint) {
    let cache = rte_mempool_default_cache(mp, rte_lcore_id_stub());
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
        cache = rte_mempool_default_cache(mp, rte_lcore_id_stub());
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
    let mut m = m.as_mut_ptr() as *mut c_void;
    let ptr = addr_of_mut!(m);
    if rte_mempool_get(mp, ptr) < 0 {
        return ptr::null_mut();
    }
    m as *mut rte_mbuf
}

#[inline(always)]
unsafe fn rte_mbuf_raw_free(m: *mut rte_mbuf) {
    assert!((*m).ol_flags & RTE_MBUF_F_INDIRECT == 0);
    assert!(
        (*m).ol_flags & RTE_MBUF_F_EXTERNAL == 0
            || rte_pktmbuf_priv_flags((*m).pool) & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF != 0
    );
    __rte_mbuf_raw_sanity_check(m);
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
pub unsafe fn rte_pktmbuf_alloc_bulk(
    mp: *mut rte_mempool,
    mbufs: *mut *mut rte_mbuf,
    count: c_uint,
) -> c_int {
    let rc = rte_mempool_get_bulk(mp, mbufs as *mut *mut c_void, count);
    if rc > 0 {
        return rc;
    }
    for idx in 0..count {
        rte_pktmbuf_reset((*mbufs).add(idx as _));
    }
    0
}

#[inline]
pub unsafe fn rte_mbuf_buf_addr(mb: *const rte_mbuf, mp: *const rte_mempool) -> *mut c_char {
    let mb = rte_mbuf_from_indirect(mb);
    (mb as *mut c_char).add(mem::size_of::<rte_mbuf>() + rte_pktmbuf_priv_size(mp) as usize)
}

#[inline]
pub unsafe fn rte_pktmbuf_headroom(m: *mut rte_mbuf) -> c_ushort {
    (*m).data_off
}

#[inline]
pub unsafe fn rte_pktmbuf_tailroom(m: *mut rte_mbuf) -> c_ushort {
    (*m).buf_len - rte_pktmbuf_headroom(m) - (*m).data_len
}

#[inline]
pub unsafe fn rte_pktmbuf_reset(m: *mut rte_mbuf) {
    (*m).next = ptr::null_mut();
    (*m).pkt_len = 0;
    (*m).tx_offload_union.tx_offload = 0;
    (*m).vlan_tci = 0;
    (*m).vlan_tci_outer = 0;
    (*m).nb_segs = 1;
    (*m).port = RTE_MBUF_PORT_INVALID as u16;

    (*m).ol_flags &= RTE_MBUF_F_EXTERNAL;
    (*m).packet_type_union.packet_type = 0;
    rte_pktmbuf_reset_headroom(m);

    (*m).data_len = 0;
}

#[inline]
pub unsafe fn rte_pktmbuf_reset_headroom(m: *mut rte_mbuf) {
    (*m).data_off = (*m).buf_len.min(128);
}

#[inline]
unsafe fn rte_pktmbuf_detach(m: *mut rte_mbuf) {
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
pub unsafe fn rte_pktmbuf_prepend(m: *mut rte_mbuf, len: c_ushort) -> *mut c_char {
    if len > rte_pktmbuf_headroom(m) {
        return ptr::null_mut();
    }
    (*m).data_off = (*m).data_off - len;
    (*m).data_len = (*m).data_len + len;
    (*m).pkt_len = (*m).pkt_len + len as u32;
    ((*m).buf_addr as *mut c_char).add((*m).data_off as _) as *mut c_char
}

#[inline]
unsafe fn rte_pktmbuf_lastseg(mut m: *mut rte_mbuf) -> *mut rte_mbuf {
    loop {
        if (*m).next.is_null() {
            break;
        }
        m = (*m).next;
    }
    m
}

#[inline]
pub unsafe fn rte_pktmbuf_append(m: *mut rte_mbuf, len: c_ushort) -> *mut c_char {
    let m_last = rte_pktmbuf_lastseg(m);
    if len > rte_pktmbuf_tailroom(m_last) {
        return ptr::null_mut();
    }
    let tail =
        ((*m_last).buf_addr as *mut c_char).add(((*m_last).data_off + (*m_last).data_len) as usize);
    (*m_last).data_len = (*m_last).data_len + len;
    (*m).pkt_len = (*m).pkt_len + len as u32;
    tail
}

#[inline]
pub unsafe fn rte_pktmbuf_adj(m: *mut rte_mbuf, len: c_ushort) -> *mut c_char {
    if len > (*m).data_len {
        return ptr::null_mut();
    }
    (*m).data_len = (*m).data_len - len;
    (*m).data_off = (*m).data_off + len;
    (*m).pkt_len = (*m).pkt_len - len as u32;
    ((*m).buf_addr as *mut c_char).add((*m).data_off as usize) as *mut c_char
}

#[inline]
pub unsafe fn rte_pktmbuf_trim(m: *mut rte_mbuf, len: c_ushort) -> c_int {
    let m_last = rte_pktmbuf_lastseg(m);
    if len > (*m_last).data_len {
        return -1;
    }
    (*m_last).data_len = (*m_last).data_len - len;
    (*m).pkt_len = (*m).pkt_len - len as u32;
    0
}

#[inline]
pub unsafe fn rte_pktmbuf_chain(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> c_int {
    if ((*head).nb_segs + (*tail).nb_segs) as u32 > RTE_MBUF_MAX_NB_SEGS {
        return -libc::EOVERFLOW;
    }
    let cur_tail = rte_pktmbuf_lastseg(head);
    (*cur_tail).next = tail;
    (*head).nb_segs = (*head).nb_segs + (*tail).nb_segs;
    (*head).pkt_len += (*tail).pkt_len;
    (*tail).pkt_len = (*tail).data_len as u32;
    0
}

#[inline]
pub unsafe fn rte_pktmbuf_linearize(m: *mut rte_mbuf) -> c_int {
    if (*m).nb_segs == 1 {
        0
    } else {
        __rte_pktmbuf_linearize(m)
    }
}

#[inline]
unsafe fn rte_mbuf_refcnt_read(m: *const rte_mbuf) -> c_ushort {
    (*m).refcnt
}

#[inline]
unsafe fn rte_mbuf_refcnt_set(m: *mut rte_mbuf, v: c_ushort) {
    (*m).refcnt = v;
}

#[inline]
unsafe fn rte_mbuf_refcnt_update(m: *mut rte_mbuf, v: c_short) -> c_ushort {
    (*m).refcnt = (*m).refcnt.wrapping_add(v as c_ushort);
    (*m).refcnt
}

#[inline]
#[allow(dead_code)]
unsafe fn rte_pktmbuf_refcnt_update(mut m: *mut rte_mbuf, v: c_short) {
    loop {
        rte_mbuf_refcnt_update(m, v);
        m = (*m).next;
        if m.is_null() {
            break;
        }
    }
}

#[inline]
pub unsafe fn rte_mbuf_from_indirect(mi: *const rte_mbuf) -> *mut rte_mbuf {
    ((*mi).buf_addr as *mut c_char).sub(mem::size_of::<rte_mbuf>() + (*mi).priv_size as usize)
        as *mut rte_mbuf
}

#[inline]
unsafe fn rte_mbuf_ext_refcnt_read(shinfo: *mut rte_mbuf_ext_shared_info) -> c_ushort {
    let refcnt = &*(&(*shinfo).refcnt as *const u16 as *const AtomicU16);
    refcnt.load(Ordering::Relaxed)
}

#[inline]
unsafe fn rte_mbuf_ext_refcnt_set(shinfo: *mut rte_mbuf_ext_shared_info, v: c_ushort) {
    let refcnt = &*(&(*shinfo).refcnt as *const u16 as *const AtomicU16);
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
    let refcnt = &*(&(*shinfo).refcnt as *const u16 as *const AtomicU16);
    refcnt.fetch_add(v, Ordering::AcqRel) + v
}

#[inline]
unsafe fn rte_mempool_get_priv(mp: *const rte_mempool) -> *mut c_void {
    let cache_sz = (*mp).cache_size;
    let mut offset = mem::size_of::<rte_mempool>();
    if cache_sz != 0 {
        offset += mem::size_of::<rte_mempool_cache>() * RTE_MAX_LCORE as usize;
    }
    (mp as *mut c_char).add(offset) as *mut c_void
}

#[inline]
unsafe fn rte_mempool_virt2iova(elt: *const c_void) -> rte_iova_t {
    let hdr =
        (elt as *mut c_char).sub(mem::size_of::<rte_mempool_objhdr>()) as *const rte_mempool_objhdr;
    (*hdr).iova
}

#[inline]
unsafe fn rte_pktmbuf_priv_size(mp: *const rte_mempool) -> c_ushort {
    let mbp_priv = rte_mempool_get_priv(mp) as *const rte_pktmbuf_pool_private;
    (*mbp_priv).mbuf_priv_size
}

#[inline]
unsafe fn rte_pktmbuf_priv_flags(mp: *const rte_mempool) -> c_uint {
    let mbp_priv = rte_mempool_get_priv(mp) as *const rte_pktmbuf_pool_private;
    (*mbp_priv).flags
}

#[inline]
pub unsafe fn rte_pktmbuf_data_room_size(mp: *const rte_mempool) -> c_ushort {
    let mbp_priv = rte_mempool_get_priv(mp) as *mut rte_pktmbuf_pool_private;
    (*mbp_priv).mbuf_data_room_size
}

#[inline]
unsafe fn __rte_pktmbuf_copy_hdr(mdst: *mut rte_mbuf, msrc: *const rte_mbuf) {
    (*mdst).port = (*msrc).port;
    (*mdst).vlan_tci = (*msrc).vlan_tci;
    (*mdst).vlan_tci_outer = (*msrc).vlan_tci_outer;
    (*mdst).tx_offload_union.tx_offload = (*msrc).tx_offload_union.tx_offload;
    (*mdst).hash_union.hash = (*msrc).hash_union.hash;
    (*mdst).packet_type_union.packet_type = (*msrc).packet_type_union.packet_type;
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

#[inline]
unsafe fn __rte_pktmbuf_pinned_extbuf_decref(m: *mut rte_mbuf) -> c_int {
    (*m).ol_flags = RTE_MBUF_F_EXTERNAL;
    let shinfo = (*m).shinfo;
    if rte_mbuf_ext_refcnt_read(shinfo) == 1 {
        return 0;
    }
    let refcnt = &*(&(*shinfo).refcnt as *const u16 as *const AtomicU16);
    if refcnt.fetch_add(u16::MAX, Ordering::AcqRel) != 1 {
        return 1;
    }
    rte_mbuf_ext_refcnt_set(shinfo, 1);
    0
}

#[inline(always)]
unsafe fn __rte_mbuf_raw_sanity_check(m: *const rte_mbuf) {
    assert!(rte_mbuf_refcnt_read(m) == 1);
    assert!((*m).next.is_null());
    assert!((*m).nb_segs == 1);
}

#[inline]
unsafe fn __rte_mbuf_refcnt_update(m: *mut rte_mbuf, value: c_short) -> c_ushort {
    (*m).refcnt = (*m).refcnt.wrapping_add(value as u16);
    (*m).refcnt
}

#[inline(always)]
unsafe fn rte_pktmbuf_prefree_seg(m: *mut rte_mbuf) -> *mut rte_mbuf {
    if rte_mbuf_refcnt_read(m) == 1 {
        // is not direct
        if (*m).ol_flags & (RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL) != 0 {
            rte_pktmbuf_detach(m);
            if (*m).ol_flags & RTE_MBUF_F_EXTERNAL != 0
                && rte_pktmbuf_priv_flags((*m).pool) & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF != 0
                && __rte_pktmbuf_pinned_extbuf_decref(m) != 0
            {
                return ptr::null_mut();
            }

            (*m).next = ptr::null_mut();
            (*m).nb_segs = 1;

            return m;
        }
    } else if __rte_mbuf_refcnt_update(m, -1) == 0 {
        // is not direct
        if (*m).ol_flags & (RTE_MBUF_F_INDIRECT | RTE_MBUF_F_EXTERNAL) != 0 {
            rte_pktmbuf_detach(m);
            if (*m).ol_flags & RTE_MBUF_F_EXTERNAL != 0
                && rte_pktmbuf_priv_flags((*m).pool) & RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF != 0
                && __rte_pktmbuf_pinned_extbuf_decref(m) != 0
            {
                return ptr::null_mut();
            }

            (*m).next = ptr::null_mut();
            (*m).nb_segs = 1;

            rte_mbuf_refcnt_set(m, 1);
            return m;
        }
    }
    ptr::null_mut()
}

#[inline(always)]
unsafe fn rte_pktmbuf_free_seg(mut m: *mut rte_mbuf) {
    m = rte_pktmbuf_prefree_seg(m);
    if !m.is_null() {
        rte_mbuf_raw_free(m);
    }
}

#[inline]
pub unsafe fn rte_pktmbuf_free(mut m: *mut rte_mbuf) {
    loop {
        if m.is_null() {
            break;
        }
        let m_next = (*m).next;
        rte_pktmbuf_free_seg(m);
        m = m_next;
    }
}

#[inline]
pub unsafe fn rte_eth_rx_burst(
    port_id: u16,
    queue_id: u16,
    rx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> u16 {
    if port_id >= RTE_MAX_ETHPORTS as u16 || queue_id >= RTE_MAX_QUEUES_PER_PORT as u16 {
        return 0;
    }
    let p = &rte_eth_fp_ops[port_id as usize];
    let qd = *p.rxq.data.add(queue_id as _);
    if qd.is_null() {
        return 0;
    }
    if let Some(rx_pkt_burst) = (*p).rx_pkt_burst {
        rx_pkt_burst(qd, rx_pkts, nb_pkts)
    } else {
        0
    }
}

#[inline]
pub unsafe fn rte_eth_tx_burst(
    port_id: c_ushort,
    queue_id: c_ushort,
    tx_pkts: *mut *mut rte_mbuf,
    mut nb_pkts: c_ushort,
) -> c_ushort {
    let p = &rte_eth_fp_ops[port_id as usize];
    let qd = *p.txq.data.add(queue_id as _);

    if let Some(tx_pkt_burst) = p.tx_pkt_burst {
        nb_pkts = tx_pkt_burst(qd, tx_pkts, nb_pkts);
    }

    nb_pkts
}

#[inline]
pub unsafe fn rte_ether_addr_copy(ea_from: *const rte_ether_addr, ea_to: *mut rte_ether_addr) {
    *ea_to = *ea_from;
}

#[inline]
unsafe fn __rte_raw_cksum(buf: *const c_void, len: usize, mut sum: c_uint) -> c_uint {
    let mut u16_buf = buf as *const c_ushort;
    let end = u16_buf.add(len / mem::size_of::<c_ushort>());

    while u16_buf != end {
        sum += *u16_buf as u32;
        u16_buf = u16_buf.add(1);
    }

    if len % 2 == 1 {
        let left = end as *const c_char;
        sum += *left as u32;
    }
    sum
}

#[inline]
unsafe fn __rte_raw_cksum_reduce(mut sum: c_uint) -> c_ushort {
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum as c_ushort
}

#[inline]
unsafe fn rte_raw_cksum(buf: *const c_void, len: usize) -> c_ushort {
    let sum = __rte_raw_cksum(buf, len, 0);
    __rte_raw_cksum_reduce(sum)
}

#[inline]
unsafe fn rte_ipv4_hdr_len(ipv4_hdr: *const rte_ipv4_hdr) -> c_uchar {
    ((*ipv4_hdr).version_ihl_union.version_ihl & RTE_IPV4_HDR_IHL_MASK as u8)
        * RTE_IPV4_IHL_MULTIPLIER as u8
}

#[inline]
pub unsafe fn rte_ipv4_cksum(ipv4_hdr: *const rte_ipv4_hdr) -> c_ushort {
    let cksum = rte_raw_cksum(ipv4_hdr as _, rte_ipv4_hdr_len(ipv4_hdr) as _);
    !cksum as c_ushort
}

#[inline]
pub unsafe fn rte_ipv4_frag_pkt_is_fragmented(hdr: *const rte_ipv4_hdr) -> c_int {
    let frag_offset = u16::from_be((*hdr).fragment_offset);
    let ip_ofs = frag_offset & RTE_IPV4_HDR_OFFSET_MASK as u16;
    let ip_frag = frag_offset & RTE_IPV4_HDR_MF_FLAG as u16;
    if ip_ofs != 0 || ip_frag != 0 {
        1
    } else {
        0
    }
}

#[inline(always)]
pub unsafe fn rte_rdtsc() -> c_ulong {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut tsc_lo: u32;
        let mut tsc_hi: u32;
        asm!("rdtsc", out("rax") tsc_lo, out("rdx") tsc_hi, clobber_abi("C"));
        ((tsc_hi as u64) << 32) | tsc_lo as u64
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        #[allow(unused_assignments)] // to fool the compiler
        let mut tsc: u64 = 0;
        asm!("mrs {0}, cntvct_el0", out(reg) tsc);
        tsc
    }
}
