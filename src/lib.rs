#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod consts;
mod inline;
pub mod macros;
mod types;

pub use consts::*;
pub use inline::*;
pub use types::*;
