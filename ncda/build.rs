use std::{fs, path::PathBuf, process::Command};

use anyhow::{anyhow, ensure, Context as _};
use aya_build::Toolchain;

const EBPF_OBJECT_ENV: &str = "NCDA_EBPF_OBJECT";
const EBPF_TARGET_ARCH_ENV: &str = "NCDA_EBPF_TARGET_ARCH";
const EBPF_TOOLCHAIN: &str = "nightly-2026-08-04";
const REQUIRED_EBPF_MAPS: &[&str] = &["EVENTS", "CAPTURE_STATS"];
const REQUIRED_EBPF_PROGRAMS: &[&str] = &[
    "sys_enter",
    "sys_exit",
    "sched_process_exec",
    "sched_process_exit_group",
    "sched_process_exit_legacy",
    "taskstats_process_exit",
];

fn main() -> anyhow::Result<()> {
    println!(
        "cargo:rustc-env=NCDA_BUILD_TARGET={}",
        std::env::var("TARGET")?
    );
    println!("cargo:rerun-if-env-changed=NCDA_EBPF_TOOLCHAIN");
    let ebpf_toolchain =
        std::env::var("NCDA_EBPF_TOOLCHAIN").unwrap_or_else(|_| EBPF_TOOLCHAIN.to_string());
    println!("cargo:rustc-env=NCDA_EBPF_TOOLCHAIN={ebpf_toolchain}");
    export_tool_version("NCDA_RUSTC_VERSION", "rustc", &["--version"]);
    export_tool_version("NCDA_BPF_LINKER_VERSION", "bpf-linker", &["--version"]);

    println!("cargo:rerun-if-env-changed={EBPF_OBJECT_ENV}");
    if let Some(source) = std::env::var_os(EBPF_OBJECT_ENV) {
        let source = PathBuf::from(source);
        if source.as_os_str().is_empty() {
            return Err(anyhow!("{EBPF_OBJECT_ENV} must not be empty"));
        }
        println!("cargo:rerun-if-env-changed={EBPF_TARGET_ARCH_ENV}");
        let ebpf_arch = required_environment(EBPF_TARGET_ARCH_ENV)?;
        let userspace_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
        ensure!(
            ebpf_arch == userspace_arch,
            "prebuilt eBPF architecture {ebpf_arch} does not match userspace architecture {userspace_arch}"
        );
        required_environment("NCDA_EBPF_TOOLCHAIN")?;
        required_environment("NCDA_BPF_LINKER_VERSION")?;

        println!("cargo:rerun-if-changed={}", source.display());
        let bytes = fs::read(&source)
            .with_context(|| format!("reading prebuilt eBPF object from {}", source.display()))?;
        validate_ebpf_object(&bytes).with_context(|| {
            format!("validating prebuilt eBPF object from {}", source.display())
        })?;

        let destination =
            PathBuf::from(std::env::var_os("OUT_DIR").context("OUT_DIR is not set")?).join("ncda");
        fs::write(&destination, bytes).with_context(|| {
            format!(
                "writing prebuilt eBPF object from {} to {}",
                source.display(),
                destination.display()
            )
        })?;
        return Ok(());
    }

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

    // The pinned bpf-linker 0.11 uses LLVM 22. Keep the eBPF compiler on the
    // same LLVM major; newer LLVM bitcode is not compatible.
    aya_build::build_ebpf([ebpf_package], Toolchain::Custom(&ebpf_toolchain))
}

fn required_environment(variable: &str) -> anyhow::Result<String> {
    std::env::var(variable)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("{variable} must be set when {EBPF_OBJECT_ENV} is used"))
}

fn validate_ebpf_object(bytes: &[u8]) -> anyhow::Result<()> {
    let object = aya_obj::Object::parse(bytes).context("parsing ELF object")?;
    ensure!(object.btf.is_some(), "eBPF object has no BTF metadata");
    ensure!(
        object.btf_ext.is_some(),
        "eBPF object has no extended BTF metadata"
    );
    for name in REQUIRED_EBPF_MAPS {
        ensure!(
            object.maps.contains_key(*name),
            "eBPF map {name} is missing"
        );
    }
    for name in REQUIRED_EBPF_PROGRAMS {
        ensure!(
            object.programs.contains_key(*name),
            "eBPF program {name} is missing"
        );
    }
    Ok(())
}

fn export_tool_version(variable: &str, program: &str, arguments: &[&str]) {
    println!("cargo:rerun-if-env-changed={variable}");
    let version = std::env::var(variable)
        .ok()
        .filter(|version| !version.trim().is_empty())
        .unwrap_or_else(|| {
            Command::new(program)
                .args(arguments)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|version| version.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
    println!("cargo:rustc-env={variable}={version}");
}
