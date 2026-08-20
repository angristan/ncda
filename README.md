# ncda

Like [ncdu](https://dev.yorhel.nl/ncdu), but for live file I/O. Uses eBPF to monitor `openat`, `read`, `write`, and `close` syscalls system-wide and displays activity in an interactive TUI.

Built with [Aya](https://aya-rs.dev/) and [Ratatui](https://ratatui.rs/).

## Requirements

- Linux 6.1+ on x86_64 or arm64
- Root privileges (eBPF needs `CAP_BPF`)
- Rust nightly `nightly-2026-08-04` + `bpf-linker` (for building)

## Usage

```bash
sudo ncda          # interactive TUI
sudo ncda --stdout # periodic text summary
```

## Building

```bash
cargo build --release
```

Requires `nightly-2026-08-04` with `rust-src` and `bpf-linker`. The nightly is pinned because its LLVM 22 bitcode matches `bpf-linker` 0.11 on Arch; LLVM bitcode is not forward-compatible across major versions.

ncda uses the global raw syscall tracepoints with compile-time register and syscall-number decoders for x86_64 and arm64. Arm64 has no native `dup2`; libc uses `dup3` instead.
