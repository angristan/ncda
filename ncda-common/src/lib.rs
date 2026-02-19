#![no_std]

/// Maximum filename length captured in eBPF events.
pub const MAX_FNAME_LEN: usize = 256;

// Event kind discriminants
pub const EVENT_OPEN: u32 = 1;
pub const EVENT_READ: u32 = 2;
pub const EVENT_WRITE: u32 = 3;
pub const EVENT_CLOSE: u32 = 4;

/// Open event — includes the filename captured at openat() time.
/// Sent from eBPF to userspace via RingBuf.
/// Size: 24 + 256 = 280 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub fname_len: u32,
    pub _pad: u32,
    pub fname: [u8; MAX_FNAME_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenEvent {}

/// I/O event — used for Read, Write, and Close events.
/// Sent from eBPF to userspace via RingBuf.
/// Size: 32 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub fd: u32,
    pub bytes: u64,
    pub latency_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IoEvent {}

/// Stash for openat entry → exit correlation.
/// Stored in a HashMap keyed by pid_tgid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenArgs {
    pub fname: [u8; MAX_FNAME_LEN],
    pub fname_len: u32,
    pub flags: u32,
}

/// Stash for read/write entry → exit correlation.
/// Stored in a HashMap keyed by pid_tgid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RwArgs {
    pub ts: u64,
    pub fd: u32,
    pub _pad: u32,
}
