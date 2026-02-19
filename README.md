# ncda

Like [ncdu](https://dev.yorhel.nl/ncdu), but for live file I/O. Uses eBPF to monitor `openat`, `read`, `write`, and `close` syscalls system-wide and displays activity in an interactive TUI.

Built with [Aya](https://aya-rs.dev/) and [Ratatui](https://ratatui.rs/).

## Requirements

- Linux 6.1+
- Root privileges (eBPF needs `CAP_BPF`)
- Rust nightly + `bpf-linker` (for building)

## Usage

```bash
sudo ncda          # interactive TUI
sudo ncda --stdout # periodic text summary
```

## Building

```bash
cargo build --release
```

Requires Rust nightly, `bpf-linker`, and `rust-src`.
