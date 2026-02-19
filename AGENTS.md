# AGENTS.md

## Project

**ncda** -- an ncdu-like TUI for monitoring live file I/O on Linux using eBPF (Aya framework).

Hooks into kernel syscall tracepoints (`openat`, `read`, `write`, `close`) to capture file access in real-time. Displays activity in an interactive terminal UI with flat (ncdu-style) and tree views.

## Architecture

```
Kernel (eBPF tracepoints)
  -> RingBuf (16 MiB)
    -> Polling reader task (10ms)
      -> mpsc channel
        -> Aggregator (AppState)
          -> TUI (ratatui) or stdout mode
```

Three crates in one workspace:

| Crate | Role |
|-------|------|
| `ncda-common` | `#![no_std]` shared types (`OpenEvent`, `IoEvent`, constants) |
| `ncda-ebpf` | eBPF programs (7 tracepoint handlers), compiled to `bpfel-unknown-none` |
| `ncda` | Userspace binary: eBPF loader, event parser, data model, TUI |

## Build

### Requirements

- **Rust nightly** (needs `-Zbuild-std` for eBPF target)
- `bpf-linker` (`cargo install bpf-linker`)
- `rustup component add rust-src`
- `clang` and `llvm` (for eBPF compilation)
- Linux 6.1+ kernel at runtime

### Development on macOS

The aya crate is Linux-only. To type-check userspace code on macOS:

```bash
AYA_BUILD_SKIP=1 cargo check --package ncda --target aarch64-unknown-linux-gnu
```

This skips the eBPF build. The `include_bytes_aligned!` error for the missing eBPF binary is expected and unavoidable in this mode.

### Full build on Linux

```bash
cargo build            # debug
cargo build --release  # release
```

`ncda/build.rs` invokes `aya-build` which compiles `ncda-ebpf` into eBPF bytecode automatically.

### Cross-compile for x86_64 from arm64

```bash
rustup target add x86_64-unknown-linux-gnu
apt install gcc-x86-64-linux-gnu   # or equivalent
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  cargo build --release --target x86_64-unknown-linux-gnu
```

### Testing with OrbStack (from macOS)

An OrbStack VM named `ncda-test` (Debian Bookworm, arm64) exists for testing:

```bash
# Shell in as root
orb -m ncda-test -u root

# Inside VM
source $HOME/.cargo/env
cd ~/ncda
cargo build
sudo ./target/debug/ncda --stdout
```

To sync local changes into the VM before rebuilding:

```bash
orb -m ncda-test bash -c '
  cp -r /Users/stanislas/lab/ncda/ncda-ebpf/src ~/ncda/ncda-ebpf/src
  cp -r /Users/stanislas/lab/ncda/ncda/src ~/ncda/ncda/src
'
```

## Running

Requires root (eBPF needs `CAP_BPF` / `CAP_SYS_ADMIN`):

```bash
sudo ./target/debug/ncda          # TUI mode
sudo ./target/debug/ncda --stdout # periodic text summary
sudo ./target/debug/ncda -v       # verbose logging
```

## Code map

### `ncda-ebpf/src/main.rs`
Seven tracepoint handlers. Five eBPF maps:
- `EVENTS` -- RingBuf for kernel-to-user event delivery
- `OPEN_STASH` / `RW_STASH` -- HashMaps correlating syscall entry/exit pairs
- `SCRATCH` / `EVENT_BUF` -- PerCpuArray scratch buffers (avoids 512-byte stack limit)

### `ncda/src/bpf.rs`
eBPF loader, tracepoint attachment, ring buffer polling, raw event parsing, `FdPathCache` (pid,fd -> path mapping in userspace).

### `ncda/src/model.rs`
`FileTree` with `TreeNode` hierarchy. `NodeStats` for aggregated I/O metrics. `SortBy` enum with 6 criteria. `record()` walks path components, updates leaf stats, propagates aggregates upward.

### `ncda/src/tui/app.rs`
`AppState` -- shared state holding tree, fd cache, process table, rate tracker, event log. `ingest()` processes batches of `BpfEvent`s. `ViewState` -- TUI-local navigation state.

### `ncda/src/tui/`
- `flat_view.rs` -- ncdu-style directory listing with bar graphs
- `tree_view.rs` -- expandable tree with flatten logic
- `input.rs` -- keybinding dispatch
- `header.rs` / `footer.rs` -- chrome
- `mod.rs` -- main render loop, help overlay, process panel

## Key design decisions

- **Tracepoints over fentry/fexit**: More portable, avoids `bpf_d_path` complexity.
- **Path resolution in userspace**: eBPF captures filenames at `openat` only. The `FdPathCache` in userspace maps (pid, fd) to paths. Read/write events carry only fd + byte count.
- **PerCpuArray scratch buffers**: `OpenArgs` is 264 bytes, too large for reliable eBPF stack use. Scratch buffers avoid hitting the 512-byte stack limit.
- **Owned `RingBuf<MapData>`**: Uses `Ebpf::take_map()` (not `map_mut()`) so the ring buffer can be moved into a `'static` tokio task.
- **Polling over async**: `reader_loop_polling` (10ms sleep) is used instead of `AsyncFd`-based epoll for reliability. The async `reader_loop` exists but is unused.

## eBPF API notes

These apply to the current aya-ebpf version (git HEAD):
- `HashMap::get()` requires `unsafe`; `HashMap::insert()` and `HashMap::remove()` do **not**.
- `PerCpuArray::get_ptr_mut()` does **not** require `unsafe`.
- `RingBuf::output()` needs turbofish type annotation: `EVENTS.output::<IoEvent>(&event, 0)` -- otherwise `Borrow<T>` is ambiguous.
- `EbpfLogger::init()` is self-contained (spawns its own tokio tasks). Do not wrap in `AsyncFd`.
