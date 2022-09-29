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
    pub type_struct: pkt_type_struct_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pkt_type_struct_t {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize]>,
    pub _inner_esp_next_proto_union: inner_esp_next_proto_union_t,
    pub _bitfield_align_2: [u8; 0],
    pub _bitfield_2: __BindgenBitfieldUnit<[u8; 1usize]>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union inner_esp_next_proto_union_t {
    pub _inner_esp_next_proto: u8,
    pub _inner_esp_next_proto_struct: inner_esp_next_proto_struct_t,
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
    pub hash_id_union: hash_id_union_t,
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
pub union hash_id_union_t {
    pub hash_id_struct: hash_id_struct_t,
    pub lo: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct hash_id_struct_t {
    pub hash: u16,
    pub id: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union tx_offload_union_t {
    pub tx_offload: u64,
    pub tx_offload_struct: tx_offload_struct_t,
}

#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Default, Copy, Clone)]
pub struct tx_offload_struct_t {
    pub _bitfield_align_1: [u16; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 7usize]>,
}

impl tx_offload_struct_t {
    #[inline]
    pub fn l2_len(&self) -> u16 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 7u8) as u16) }
    }
    #[inline]
    pub fn set_l2_len(&mut self, val: u16) {
        let val: u16 = unsafe { ::std::mem::transmute(val) };
        self._bitfield_1.set(0usize, 7u8, val as u64)
    }
    #[inline]
    pub fn l3_len(&self) -> u16 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(7usize, 9u8) as u16) }
    }
    #[inline]
    pub fn set_l3_len(&mut self, val: u16) {
        let val: u16 = unsafe { ::std::mem::transmute(val) };
        self._bitfield_1.set(7usize, 9u8, val as u64)
    }
    #[inline]
    pub fn l4_len(&self) -> u16 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(16usize, 8u8) as u16) }
    }
    #[inline]
    pub fn set_l4_len(&mut self, val: u16) {
        let val: u16 = unsafe { ::std::mem::transmute(val) };
        self._bitfield_1.set(16usize, 8u8, val as u64)
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct rte_ipv4_hdr {
    pub version_ihl_union: version_ihl_union_t,
    pub type_of_service: u8,
    pub total_length: rte_be16_t,
    pub packet_id: rte_be16_t,
    pub fragment_offset: rte_be16_t,
    pub time_to_live: u8,
    pub next_proto_id: u8,
    pub hdr_checksum: rte_be16_t,
    pub src_addr: rte_be32_t,
    pub dst_addr: rte_be32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union version_ihl_union_t {
    pub version_ihl: u8,
    pub version_ihl_struct: version_ihl_struct_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct version_ihl_struct_t {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
}

impl version_ihl_struct_t {
    #[inline]
    pub fn ihl(&self) -> u8 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_ihl(&mut self, val: u8) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(ihl: u8, version: u8) -> __BindgenBitfieldUnit<[u8; 1usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { ::std::mem::transmute(ihl) };
            ihl as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { ::std::mem::transmute(version) };
            version as u64
        });
        __bindgen_bitfield_unit
    }
}
