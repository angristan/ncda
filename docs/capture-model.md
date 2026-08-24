# Capture model

`ncda` observes file I/O system-wide and resolves file descriptors to paths in userspace.

## Coverage

Capture includes:

- `openat` and `openat2`
- scalar, positional, vectored, and v2 reads and writes
- `dup`, `dup2`, `dup3`, and duplicating `fcntl` commands
- `close`, `close_range`, process exec, and final process exit

Only successful calls that transfer at least one byte contribute to byte totals, operation counts, rates, and average syscall latency. Failed and zero-byte calls are separate diagnostics.

## Path attribution

Descriptor state is invalidated when a descriptor is replaced or closed, across exec, and after the final thread exits. Relative paths are accepted only when they still match the descriptor target in procfs.

When attribution is ambiguous, activity is placed under `/[unresolved]/pid-<pid>/...`. Truncated and unreadable path captures use the same namespace. Linux pathname bytes are preserved; bytes that are unsafe to print are shown with reversible `\\xNN` escapes.

Memory-backed descriptors are grouped under `/[memory]/`. Sockets, pipes, and other non-file pseudo descriptors are not shown.

## Loss and shutdown

`Drops` combines kernel ring/stash/scratch loss with userspace parse/queue loss. Any increase means the displayed activity is incomplete. It also clears cached descriptor attribution before later events are processed, preventing stale paths from being reused.

On shutdown, producers detach before the ring is drained. Pending application aggregation may then be discarded because the output is already closed; this intentional discard is reported separately in verbose logs.
