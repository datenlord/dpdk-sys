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

    for lib in libdpdk.libs {
        println!("cargo:rustc-link-lib={lib}");
    }

    for path in libdpdk.link_paths {
        let path = path.to_string_lossy();
        println!("cargo:rustc-link-search=native={path}");
    }

    let include_args = libdpdk
        .include_paths
        .iter()
        .map(|p| format!("-I{}", p.to_str().unwrap()))
        .collect::<Vec<String>>();

    let bindings = bindgen::builder()
        .clang_args(include_args)
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_type("rte_.*")
        .allowlist_var("RTE_.*")
        .allowlist_var("rte_.*")
        .allowlist_function("rte_.*")
        .allowlist_function("__rte_pktmbuf_.*")
        .blocklist_function("rte_flow_.*")
        .blocklist_item("rte_flow_.*")
        .blocklist_type("rte_flow_.*")
        .blocklist_type("rte_mbuf")
        .blocklist_type("rte_arp_ipv4")
        .blocklist_type("rte_arp_hdr")
        .blocklist_type("rte_ecpri_common_hdr")
        .blocklist_type("rte_ecpri_combined_msg_hdr")
        .blocklist_type("rte_l2tpv2_common_hdr")
        .blocklist_type("rte_l2tpv2_combined_msg_hdr")
        .blocklist_type("rte_ipv4_hdr")
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
