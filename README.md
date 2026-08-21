# ncda

`ncda` is an ncdu-like terminal monitor for live Linux file I/O. It uses eBPF raw syscall tracepoints and shows system-wide activity as a navigable directory tree, a flat directory view, or periodic text output.

Built with [Aya](https://aya-rs.dev/) and [Ratatui](https://ratatui.rs/).

## Requirements

- Linux 6.1 or newer (supported and tested baseline)
- Native x86_64 or AArch64 userspace
- Root, or an equivalent set of eBPF, tracing, and memory-lock capabilities
- Rust 1.97.1 plus `nightly-2026-08-04`, `rust-src`, and `bpf-linker` 0.11 to build

The eBPF ring buffer exists since Linux 5.8, but kernels older than 6.1 are not part of the tested support range. The syscall decoder does not support x86 ia32/x32 or ARM AArch32 compatibility ABIs.

## Install

### Homebrew on Linux

```bash
brew install angristan/tap/ncda
```

The formula installs both `ncda` and `ncda-bench` from static x86_64 or ARM64 release binaries.

### Prebuilt release

Linux x86_64 and ARM64 archives, SHA-256 checksums, and build provenance are published on the [GitHub releases page](https://github.com/angristan/ncda/releases).

### Build from source

```bash
rustup toolchain install 1.97.1
rustup toolchain install nightly-2026-08-04 --profile minimal --component rust-src
cargo install bpf-linker --version 0.11
cargo build --release --locked --bins
sudo install -m 0755 target/release/ncda /usr/local/bin/ncda
```

The eBPF nightly is pinned because its LLVM 22 bitcode matches `bpf-linker` 0.11. LLVM bitcode is not forward-compatible across major versions.

## Usage

```bash
ncda --help
sudo ncda                         # interactive TUI
sudo ncda --stdout                # periodic text summary
sudo ncda --rate-window 10        # 10-second rolling rates
sudo ncda --exclude /var/cache    # repeatable path exclusion
sudo ncda --verbose
```

Default exclusions are `/proc`, `/sys`, and `/dev`. Exclusions match complete path components: `/proc` excludes `/proc/1/status`, not `/procfoo`. They apply before container names are added, so host and container paths have the same behavior.

The TUI supports flat and tree views, path/PID/process/container filters, sortable process activity, and a built-in `?` help screen.

## Capture and attribution semantics

`ncda` covers:

- `openat` and `openat2`;
- `read`, `write`, `pread64`, and `pwrite64`;
- `readv`, `writev`, `preadv`, `pwritev`, `preadv2`, and `pwritev2`;
- `dup`, `dup2`, `dup3`, and duplicating `fcntl` commands;
- `close`, `close_range`, process exec, and process exit.

Byte counts, operation counts, rates, and average syscall latency include only successful operations that transferred at least one byte. Latency is measured in the kernel from syscall entry to syscall exit; it excludes ring delivery and UI processing. Failed completions and successful zero-byte completions are captured separately as `Err` and `Zero` diagnostics.

Path attribution is fail-safe. Descriptor replacement, range close, exec, and exit invalidate cached state. If a delayed relative open no longer matches the current descriptor target, activity is placed under `/[unresolved]/pid-<pid>/fd-<fd>/` instead of being assigned to a possibly wrong file. `Attr` counts attribution failures. Anonymous memory files are grouped under `/[memory]/`; sockets, pipes, and other non-file pseudo descriptors are hidden.

`Drops` reports kernel ring/stash/scratch loss and userspace parse/queue loss. Any non-zero drop count means displayed activity is incomplete.

## Benchmarking

`ncda-bench` generates positional file I/O and emits JSON with throughput, exact event/byte recall, syscall latency, delivery latency, capture counters, loss counters, and environment metadata.

```bash
cargo build --release --locked --bin ncda-bench
sudo ./target/release/ncda-bench \
  --warmup-seconds 2 --duration-seconds 30 \
  --threads 1 --mode mixed --block-size 4096 \
  --output ncda-benchmark.json
```

Observed events are restricted to the benchmark PID and measurement timestamps. Kernel capture/drop counters are system-wide measurement deltas. Userspace drop counters cover measurement through final drain. Unrelated host activity can therefore affect global counters even though it cannot affect workload recall. Run on an otherwise idle host, use separate read/write/mixed profiles, repeat each profile at least five times, and reject runs with drops or recall below `1.0`. Latency sample storage is capped at one million events.

## Testing

Unprivileged quality checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked --bins
```

The live-kernel suite validates syscall, descriptor-lifecycle, loss-accounting, and final-drain behavior. It builds without elevation and runs only the test executable through sanitized non-interactive `sudo`:

```bash
scripts/test-ebpf.sh
```

## License

Repository source is licensed under the [MIT License](LICENSE). The eBPF object declares `Dual MIT/GPL` as kernel-loader metadata so GPL-only helpers remain available; this does not change the repository source license.
