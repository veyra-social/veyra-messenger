fn main() {
    let nodes = std::path::Path::new("deployment/bootstrap_nodes.rs");
    println!("cargo:rustc-check-cfg=cfg(veyra_deployment_nodes)");
    println!("cargo:rerun-if-changed={}", nodes.display());
    if nodes.try_exists().expect("check bootstrap configuration") {
        println!("cargo:rustc-cfg=veyra_deployment_nodes");
    }
    tauri_build::build();
}
