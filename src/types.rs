use crate::*;

#[repr(C)]
#[repr(align(64))]
pub struct rte_mbuf {
    pub cacheline0: RTE_MARKER,
    pub buf_addr: *mut ::std::os::raw::c_void,
    pub buf_iova: rte_iova_t,
    pub rearm_data: RTE_MARKER64,
    pub data_off: u16,
    pub refcnt: u16,
    pub nb_segs: u16,
    pub port: u16,
    pub ol_flags: u64,
    pub rx_descriptor_fields1: RTE_MARKER,
    pub packet_type_union: packet_type_union_t,
    pub pkt_len: u32,
    pub data_len: u16,
    pub vlan_tci: u16,
    pub hash_union: hash_union_t,
    pub vlan_tci_outer: u16,
    pub buf_len: u16,
    pub pool: *mut rte_mempool,
    pub cacheline1: RTE_MARKER,
    pub next: *mut rte_mbuf,
    pub tx_offload_union: tx_offload_union_t,
    pub shinfo: *mut rte_mbuf_ext_shared_info,
    pub priv_size: u16,
    pub timesync: u16,
    pub dynfield1: [u32; 9usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union packet_type_union_t {
    pub packet_type: u32,
    pub __bindgen_anon_1: pkt_type_struct_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pkt_type_struct_t {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize]>,
    pub __bindgen_anon_1: inner_esp_next_proto_union_t,
    pub _bitfield_align_2: [u8; 0],
    pub _bitfield_2: __BindgenBitfieldUnit<[u8; 1usize]>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union inner_esp_next_proto_union_t {
    pub inner_esp_next_proto: u8,
    pub __bindgen_anon_1: inner_esp_next_proto_struct_t,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct inner_esp_next_proto_struct_t {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union hash_union_t {
    pub hash: hash_inner_union_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union hash_inner_union_t {
    pub rss: u32,
    pub fdir: fdir_struct_t,
    pub sched: rte_mbuf_sched,
    pub txadapter: txadapter_struct_t,
    pub usr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fdir_struct_t {
    pub __bindgen_anon_1: rte_mbuf__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1,
    pub hi: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct txadapter_struct_t {
    pub reserved1: u32,
    pub reserved2: u16,
    pub txq: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union rte_mbuf__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1 {
    pub __bindgen_anon_1:
        rte_mbuf__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1,
    pub lo: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct rte_mbuf__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1__bindgen_ty_1 {
    pub hash: u16,
    pub id: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union tx_offload_union_t {
    pub tx_offload: u64,
    pub __bindgen_anon_1: tx_offload_struct_t,
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct tx_offload_struct_t {
    pub _bitfield_align_1: [u16; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 7usize]>,
}
