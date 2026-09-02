# Nix packaging

The flake builds ncda from the repository source. The package version comes
from the workspace `Cargo.toml`, so release commits do not need a second Nix
version update.

ncda has two compiler contexts:

- userspace uses Rust 1.97.1;
- eBPF uses `nightly-2026-08-04` with `rust-src` and bpf-linker 0.11.0.

Both Rust toolchains come from the pinned rust-overlay input. bpf-linker is
built against LLVM 22 because the eBPF nightly emits LLVM 22 bitcode. Its local
expression matches the upstream 0.11.0 Nixpkgs package and prevents an older
bpf-linker from entering the build when the selected Nixpkgs revision lags.

Aya invokes nested eBPF builds through `rustup run`. `rustup-shim.nix` implements
only that interface and dispatches to the immutable nightly toolchain. It does
not install or update toolchains.

`package.nix` vendors the complete Cargo dependency graph as one fixed-output
derivation. This includes the Aya Git revision locked in `Cargo.lock`; neither
the userspace nor nested eBPF build accesses the network.

Validate changes on both supported architectures:

```bash
nix flake check --no-update-lock-file --print-build-logs
```

Live eBPF tests stay outside the Nix checks because they require elevated
privileges. The existing trusted CI path owns those tests.
