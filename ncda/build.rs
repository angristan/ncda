use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../ncda-ebpf/src");
    println!("cargo:rerun-if-changed=../ncda-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../ncda-common/src");
    println!("cargo:rerun-if-changed=../ncda-common/Cargo.toml");

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "ncda-ebpf")
        .ok_or_else(|| anyhow!("ncda-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    // Keep the nested Cargo build quiet on success; aya-build forwards all
    // child stderr as warnings. Compilation errors are still forwarded.
    std::env::set_var("CARGO_TERM_QUIET", "true");

    // Arch's bpf-linker 0.11 is linked against LLVM 22. Keep the eBPF
    // compiler on the same LLVM major; newer LLVM bitcode is not compatible.
    aya_build::build_ebpf([ebpf_package], Toolchain::Custom("nightly-2026-08-04"))
}
