//! Some DPDK-defined constant values.
#![allow(dead_code)]
pub const RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE: u64 = 0x10000;

pub const RTE_ETHER_ADDR_LEN: usize = 6;
pub const RTE_ETHER_TYPE_LEN: usize = 2;
pub const RTE_ETHER_CRC_LEN: usize = 4;

pub const RTE_ETHER_LOCAL_ADMIN_ADDR: u8 = 0x02;
pub const RTE_ETHER_GROUP_ADDR: u8 = 0x01;

pub const RTE_ETHER_TYPE_IPV4: u16 = 0x0800;
pub const RTE_ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const RTE_ETHER_TYPE_ARP: u16 = 0x0806;
