# Nix packaging

The flake builds ncda from the repository source. The package version comes
from the workspace `Cargo.toml`, so release commits do not need a second Nix
version update.

ncda has two isolated compiler contexts:

- `ebpf.nix` builds the kernel object with `nightly-2026-08-04`, `rust-src`, and
  bpf-linker 0.11.0;
- `package.nix` builds the userspace binaries with Rust 1.97.1 and embeds that
  prebuilt object through `NCDA_EBPF_OBJECT`.

Both Rust toolchains come from the pinned rust-overlay input. bpf-linker is
built against LLVM 22 because the eBPF nightly emits LLVM 22 bitcode. Its local
expression matches the upstream 0.11.0 Nixpkgs package and prevents an older
bpf-linker from entering the build when the selected Nixpkgs revision lags.

The eBPF derivation imports the workspace dependency graph and the registry
crates from rust-src's own lock file. `rust-std-Cargo.lock` is copied from the
Rust commit behind `nightly-2026-08-04` and must move with that pin. The stable
userspace derivation needs only the workspace dependency graph. The Aya Git
revision has an explicit output hash, and neither build stage accesses the
network.

`NCDA_EBPF_OBJECT` is a packaging interface for an object built from the same
ncda source revision. Injected objects are checked against the userspace target
architecture and parsed for ncda's required programs, maps, and BTF metadata
before they are embedded. Packagers must also provide the eBPF architecture,
toolchain, and linker metadata used by the build. When the object is absent,
the normal Cargo workflow remains unchanged: Aya starts its nested eBPF build
through the rustup toolchains documented in the main README.

The production package does not use rustup or a compatibility shim. The
default development shell retains the narrow `rustup-shim.nix` dispatcher so
normal Cargo commands rebuild changed eBPF and shared ABI sources immediately.

Validate changes on both supported architectures:

```bash
nix flake check --no-update-lock-file --print-build-logs
```

Live eBPF tests stay outside the Nix checks because they require elevated
privileges. The existing trusted CI path owns those tests.
