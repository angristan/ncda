# AGENTS.md

## Project

`ncda` is an ncdu-like Linux TUI for monitoring live file I/O with eBPF and Aya.

## Architecture

```text
raw syscall tracepoints
  -> 16 MiB eBPF RingBuf
    -> AsyncFd readiness reader (bounded batches)
      -> bounded Tokio mpsc channel
        -> AppState aggregation
          -> Ratatui TUI or stdout
```

Workspace crates:

| Crate | Role |
|---|---|
| `ncda-common` | `no_std` kernel/userspace event ABI |
| `ncda-ebpf` | eBPF raw tracepoint programs for x86_64 and AArch64 |
| `ncda` | loader, path/process enrichment, model, TUI, and benchmark |

## Build

Requirements:

- Linux on native x86_64 or AArch64
- Rust 1.97.1
- `nightly-2026-08-04` with `rust-src`
- `bpf-linker` 0.11

```bash
cargo build
cargo build --release --locked --bins
```

`ncda/build.rs` uses `aya-build` and the pinned eBPF nightly. The pin keeps LLVM 22 compatible with `bpf-linker` 0.11. Do not replace it with the default nightly without validating LLVM compatibility.

The supported runtime baseline is Linux 6.1+. Ring buffers exist since 5.8, but older kernels are not tested. The raw decoder supports native x86_64 and AArch64 only, not x86 ia32/x32 or ARM AArch32 compatibility syscalls.

## Test

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked --bins
scripts/test-ebpf.sh
```

Normal checks must remain unprivileged. `scripts/test-ebpf.sh` builds as the current user, then runs only the integration test executable with sanitized non-interactive `sudo`. CI must not run pull-request-controlled code as root.

## Capture model

Capture covers openat/openat2; scalar, positional, vectored, and v2 read/write calls; dup/dup2/dup3 and duplicating fcntl; close/close_range; exec; and final process exit.

Entry/exit stashes correlate syscalls by `pid_tgid`. Per-CPU scratch buffers avoid the eBPF stack limit. Kernel and userspace loss counters must remain visible, and any new loss must invalidate cached FD attribution.

Path resolution happens in userspace. FD state is invalidated on replacement, range close, exec, and final process exit. Raw pathname bytes must remain distinct; unsafe display bytes are escaped reversibly. Truncated, unreadable, delayed, or ambiguous paths must fail into `/[unresolved]/pid-<pid>/...`, never a plausible wrong filesystem path. Pseudo descriptors are excluded and memfds use `/[memory]/`.

Only successful positive-byte I/O contributes to bytes, operations, rates, and average syscall latency. Failed and zero-byte completions are diagnostic counters.

## Performance rules

- Keep ring drains and channels bounded.
- Do not scan all historical events for every rendered row.
- Propagate tree deltas in O(path depth); do not rescan siblings.
- Do not run external container-runtime commands while holding `AppState`.
- Bound caches and expire rolling-rate state during idle queries.

## Code map

- `ncda-ebpf/src/main.rs`: raw syscall handlers, stashes, ring output, capture counters.
- `ncda/src/bpf.rs`: loader, attachments, bounded async reader, parser, FD/path cache.
- `ncda/src/model.rs`: hierarchical aggregate model.
- `ncda/src/rate.rs`: bounded rolling-rate buckets.
- `ncda/src/container.rs`: process/container enrichment and bounded discovery commands.
- `ncda/src/tui/app.rs`: event ingestion and application state.
- `ncda/src/tui/`: rendering, input, layout, help, and panels.
- `ncda/src/bin/ncda-bench.rs`: reproducible capture benchmark.

## Benchmark

```bash
sudo ./target/release/ncda-bench --warmup-seconds 2 --duration-seconds 30 \
  --threads 1 --mode mixed --block-size 4096
```

Observed workload metrics are PID/timestamp scoped. Kernel counters are system-wide measurement deltas. Userspace drops include final drain. Keep these scopes explicit when changing the report schema.
