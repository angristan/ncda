#![no_std]

/// Maximum pathname bytes carried in an open event.
pub const MAX_FNAME_LEN: usize = 256;
/// Extra probe capacity distinguishes an exact 256-byte path from truncation.
pub const PROBE_FNAME_LEN: usize = MAX_FNAME_LEN + 2;

pub const PATH_TRUNCATED: u16 = 1 << 0;
pub const PATH_READ_FAILED: u16 = 1 << 1;
pub const PATH_KNOWN_FLAGS: u16 = PATH_TRUNCATED | PATH_READ_FAILED;

// Event kind discriminants
pub const EVENT_OPEN: u32 = 1;
pub const EVENT_READ: u32 = 2;
pub const EVENT_WRITE: u32 = 3;
pub const EVENT_CLOSE: u32 = 4;
pub const EVENT_DUP: u32 = 5;
pub const EVENT_CLOSE_RANGE: u32 = 6;
pub const EVENT_PROCESS_EXEC: u32 = 7;
pub const EVENT_PROCESS_EXIT: u32 = 8;

/// Linux `close(2)` leaves the descriptor untouched only for `EBADF`.
pub const LINUX_EBADF: i64 = 9;
/// `close_range(2)` marks descriptors close-on-exec instead of closing them.
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

pub const fn close_releases_fd(result: i64) -> bool {
    result != -LINUX_EBADF
}

/// Open event — includes the filename captured at openat() time.
/// Sent from eBPF to userspace via RingBuf.
/// Size: 32 + 256 = 288 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub fname_len: u16,
    pub fname_flags: u16,
    pub dirfd: i32,
    pub emitted_ns: u64,
    pub fname: [u8; MAX_FNAME_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenEvent {}

/// I/O event — used for Read, Write, and Close events.
/// Sent from eBPF to userspace via RingBuf.
/// Size: 40 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub result: i64,
    pub latency_ns: u64,
    pub emitted_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IoEvent {}

/// File-descriptor lifecycle event used for successful dup operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub old_fd: u32,
    pub new_fd: u32,
    pub _pad: u32,
    pub emitted_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FdEvent {}

/// Successful close_range lifecycle transition.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RangeEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub first_fd: u32,
    pub last_fd: u32,
    pub flags: u32,
    pub emitted_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RangeEvent {}

/// Process-wide lifecycle transition used for exec and exit cleanup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub kind: u32,
    pub pid: u32,
    pub emitted_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}

/// Stash for openat/openat2 entry → exit correlation.
/// Stored in a HashMap keyed by pid_tgid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenArgs {
    pub fname: [u8; PROBE_FNAME_LEN],
    pub fname_len: u16,
    pub fname_flags: u16,
    pub dirfd: i32,
}

/// Stash for read/write entry → exit correlation.
/// Stored in a HashMap keyed by pid_tgid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RwArgs {
    pub ts: u64,
    pub fd: u32,
    pub kind: u32,
}

/// Stash for close and dup entry → exit correlation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdArgs {
    pub fd: u32,
    pub _pad: u32,
}

/// Stash for close_range entry → exit correlation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RangeArgs {
    pub first_fd: u32,
    pub last_fd: u32,
    pub flags: u32,
    pub _pad: u32,
}

/// Per-CPU kernel capture failure counters.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CaptureStats {
    pub ring_output_drops: u64,
    pub stash_update_failures: u64,
    pub scratch_failures: u64,
    pub read_entries: u64,
    pub write_entries: u64,
    pub read_exits: u64,
    pub write_exits: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CaptureStats {}

// The ring-buffer ABI must be identical in eBPF and userspace builds on every
// supported architecture.
const _: [(); 288] = [(); core::mem::size_of::<OpenEvent>()];
const _: [(); 40] = [(); core::mem::size_of::<IoEvent>()];
const _: [(); 32] = [(); core::mem::size_of::<FdEvent>()];
const _: [(); 32] = [(); core::mem::size_of::<RangeEvent>()];
const _: [(); 16] = [(); core::mem::size_of::<ProcessEvent>()];
const _: [(); 56] = [(); core::mem::size_of::<CaptureStats>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_close_releases_fd_on_late_errors() {
        assert!(close_releases_fd(0));
        assert!(close_releases_fd(-5)); // EIO
        assert!(close_releases_fd(-28)); // ENOSPC
        assert!(close_releases_fd(-4)); // EINTR
        assert!(!close_releases_fd(-LINUX_EBADF));
    }
}
