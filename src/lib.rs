#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![feature(thread_local)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub const RTE_ETH_RX_OFFLOAD_TIMESTAMP: u64 = 0x10000;

mod inline;
pub mod macros;
pub mod thread_local;
mod types;

pub use inline::*;
pub use types::*;
