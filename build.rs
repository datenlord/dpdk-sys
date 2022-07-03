use pkg_config::Config;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=src/wrapper.h");

    let libdpdk = Config::new()
        .atleast_version("21.11.0")
        .probe("libdpdk")
        .expect("failed to probe dpdk");

    let include_args = libdpdk
        .include_paths
        .iter()
        .map(|p| format!("-I{}", p.to_str().unwrap()))
        .collect::<Vec<String>>();

    let bindings = bindgen::builder()
        .clang_args(include_args)
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_var("RTE_.*")
        .allowlist_var("rte_.*")
        .allowlist_function("rte_.*")
        .derive_copy(true)
        .derive_debug(false)
        .derive_default(false)
        .generate_comments(false)
        .size_t_is_usize(true)
        .rustfmt_bindings(true)
        .generate()
        .expect("failed to generate bindings to dpdk");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings");
}