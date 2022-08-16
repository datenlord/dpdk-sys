#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![feature(thread_local)]
#![feature(atomic_from_mut)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

mod inline;
mod macros;
mod thread_local;
mod types;

pub use inline::*;
pub use macros::*;
pub use thread_local::*;
pub use types::*;
