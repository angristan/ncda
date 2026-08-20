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

## Benchmarking

`ncda-bench` runs deterministic positional file I/O while observing the same process. It reports sustained capture throughput, exact event and byte recall, syscall latency, kernel-to-userspace delivery latency, tracepoint coverage, and every loss counter as JSON.

```bash
cargo build --release --locked --bin ncda-bench
sudo ./target/release/ncda-bench \
  --warmup-seconds 2 --duration-seconds 30 \
  --threads 1 --mode mixed --block-size 4096 \
  --output ncda-benchmark.json
```

Use `--mode read`, `--mode write`, and `--mode mixed` as separate profiles. Run at least five repetitions per profile on an otherwise idle host. Do not compare runs with non-zero drops or recall below `1.0`. Delivery percentiles use at most the first one million measured events to bound benchmark memory.

## Testing

Normal checks never use elevated privileges:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The ignored live-kernel suite validates openat/openat2, scalar, positional and vectored I/O, inherited descriptors, dup/dup2/dup3, close handling, loss counters, and final ring draining. Its wrapper builds as the current user, then runs only the test executable through a sanitized non-interactive sudo environment:

```bash
scripts/test-ebpf.sh
```
