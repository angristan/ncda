use which::which;

/// Causes cargo to rebuild the crate whenever the mtime of `bpf-linker` changes.
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
