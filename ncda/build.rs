use std::process::Command;

use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

const EBPF_TOOLCHAIN: &str = "nightly-2026-08-04";

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../ncda-ebpf/src");
    println!("cargo:rerun-if-changed=../ncda-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../ncda-common/src");
    println!("cargo:rerun-if-changed=../ncda-common/Cargo.toml");
    println!(
        "cargo:rustc-env=NCDA_BUILD_TARGET={}",
        std::env::var("TARGET")?
    );
    println!("cargo:rustc-env=NCDA_EBPF_TOOLCHAIN={EBPF_TOOLCHAIN}");
    export_tool_version("NCDA_RUSTC_VERSION", "rustc", &["--version"]);
    export_tool_version("NCDA_BPF_LINKER_VERSION", "bpf-linker", &["--version"]);

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
    aya_build::build_ebpf([ebpf_package], Toolchain::Custom(EBPF_TOOLCHAIN))
}

fn export_tool_version(variable: &str, program: &str, arguments: &[&str]) {
    let version = Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env={variable}={version}");
}
