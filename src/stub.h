#pragma once
#include "wrapper.h"

// Here's some stubs for inline functions in DPDK. Since Bindgen cannot generate signatures for inline
// functions, we usually rewrite them in Rust. However, there're inline functions accessing thread-local
// variables, rewriting them means that we have to add `thread_local` annotation to the type signature,
// which is a nightly feature in Rust.
//
// So we add stubs for those who is inline and also access thread-local variables.

/**
 * Return the Application thread ID of the execution unit.
*/
unsigned rte_lcore_id_stub();

/**
 * Get system unique thread id.
*/
int rte_gettid_stub();

/**
 * Get thread-local errno.
*/
int rte_errno_stub();
