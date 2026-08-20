#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ncda_common::*;

/// Ring buffer for sending events to userspace (16 MiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Entry/exit correlation maps keyed by pid_tgid.
#[map]
static OPEN_STASH: HashMap<u64, OpenArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static RW_STASH: HashMap<u64, RwArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static CLOSE_STASH: HashMap<u64, FdArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static DUP_STASH: HashMap<u64, FdArgs> = HashMap::with_max_entries(8192, 0);

/// Per-CPU scratch buffers avoid the eBPF 512-byte stack limit.
#[map]
static SCRATCH: PerCpuArray<OpenArgs> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EVENT_BUF: PerCpuArray<OpenEvent> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU loss counters avoid synchronization in syscall context.
#[map]
static CAPTURE_STATS: PerCpuArray<CaptureStats> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn record_ring_drop() {
    if let Some(stats) = CAPTURE_STATS.get_ptr_mut(0) {
        unsafe { (*stats).ring_output_drops += 1 };
    }
}

#[inline(always)]
fn record_stash_failure() {
    if let Some(stats) = CAPTURE_STATS.get_ptr_mut(0) {
        unsafe { (*stats).stash_update_failures += 1 };
    }
}

#[inline(always)]
fn record_scratch_failure() {
    if let Some(stats) = CAPTURE_STATS.get_ptr_mut(0) {
        unsafe { (*stats).scratch_failures += 1 };
    }
}

// Named syscall tracepoints expose each argument as an eight-byte field after
// the common 16-byte prefix on supported 64-bit kernels. Userspace validates
// these layouts before attachment.

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    try_sys_enter_open(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    try_sys_enter_open(&ctx).unwrap_or(0)
}

fn try_sys_enter_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let dirfd: i64 = unsafe { ctx.read_at(16)? };
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };

    let scratch = match SCRATCH.get_ptr_mut(0) {
        Some(scratch) => scratch,
        None => {
            record_scratch_failure();
            return Err(1);
        }
    };
    let args = unsafe { &mut *scratch };
    args.dirfd = dirfd as i32;
    args.fname_len = 0;

    if let Ok(filename) =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut args.fname) }
    {
        args.fname_len = filename.len() as u32;
    }

    if OPEN_STASH.insert(&pid_tgid, args, 0).is_err() {
        record_stash_failure();
        return Err(1);
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    try_sys_exit_open(&ctx).unwrap_or(0)
}

#[tracepoint]
pub fn sys_exit_openat2(ctx: TracePointContext) -> u32 {
    try_sys_exit_open(&ctx).unwrap_or(0)
}

fn try_sys_exit_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let result: i64 = unsafe { ctx.read_at(16)? };
    let stash = match unsafe { OPEN_STASH.get(&pid_tgid) } {
        Some(args) => args,
        None => return Ok(0),
    };

    if result < 0 {
        let _ = OPEN_STASH.remove(&pid_tgid);
        return Ok(0);
    }

    let buf = match EVENT_BUF.get_ptr_mut(0) {
        Some(buf) => buf,
        None => {
            record_scratch_failure();
            let _ = OPEN_STASH.remove(&pid_tgid);
            return Err(1);
        }
    };
    let event = unsafe { &mut *buf };
    event.kind = EVENT_OPEN;
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.fd = result as u32;
    event.fname_len = stash.fname_len;
    event.dirfd = stash.dirfd;

    let mut index = 0usize;
    while index < MAX_FNAME_LEN {
        event.fname[index] = stash.fname[index];
        index += 1;
    }

    if EVENTS.output::<OpenEvent>(unsafe { &*buf }, 0).is_err() {
        record_ring_drop();
    }
    let _ = OPEN_STASH.remove(&pid_tgid);
    Ok(0)
}

macro_rules! io_programs {
    ($enter:ident, $exit:ident, $kind:expr) => {
        #[tracepoint]
        pub fn $enter(ctx: TracePointContext) -> u32 {
            try_sys_enter_io(&ctx).unwrap_or(0)
        }

        #[tracepoint]
        pub fn $exit(ctx: TracePointContext) -> u32 {
            try_sys_exit_io(&ctx, $kind).unwrap_or(0)
        }
    };
}

io_programs!(sys_enter_read, sys_exit_read, EVENT_READ);
io_programs!(sys_enter_write, sys_exit_write, EVENT_WRITE);
io_programs!(sys_enter_pread64, sys_exit_pread64, EVENT_READ);
io_programs!(sys_enter_pwrite64, sys_exit_pwrite64, EVENT_WRITE);
io_programs!(sys_enter_readv, sys_exit_readv, EVENT_READ);
io_programs!(sys_enter_writev, sys_exit_writev, EVENT_WRITE);

fn try_sys_enter_io(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let args = RwArgs {
        ts: unsafe { bpf_ktime_get_ns() },
        fd: fd as u32,
        _pad: 0,
    };
    if RW_STASH.insert(&pid_tgid, &args, 0).is_err() {
        record_stash_failure();
        return Err(1);
    }
    Ok(0)
}

fn try_sys_exit_io(ctx: &TracePointContext, kind: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let result: i64 = unsafe { ctx.read_at(16)? };
    let args = match unsafe { RW_STASH.get(&pid_tgid) } {
        Some(args) => RwArgs {
            ts: args.ts,
            fd: args.fd,
            _pad: 0,
        },
        None => return Ok(0),
    };
    let _ = RW_STASH.remove(&pid_tgid);

    if result <= 0 {
        return Ok(0);
    }

    let event = IoEvent {
        kind,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        fd: args.fd,
        bytes: result as u64,
        latency_ns: unsafe { bpf_ktime_get_ns() } - args.ts,
    };
    if EVENTS.output::<IoEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    try_sys_enter_fd(&ctx, &CLOSE_STASH).unwrap_or(0)
}

#[tracepoint]
pub fn sys_exit_close(ctx: TracePointContext) -> u32 {
    try_sys_exit_close(&ctx).unwrap_or(0)
}

fn try_sys_enter_fd(ctx: &TracePointContext, stash: &HashMap<u64, FdArgs>) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let args = FdArgs {
        fd: fd as u32,
        _pad: 0,
    };
    if stash.insert(&pid_tgid, &args, 0).is_err() {
        record_stash_failure();
        return Err(1);
    }
    Ok(0)
}

fn try_sys_exit_close(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let result: i64 = unsafe { ctx.read_at(16)? };
    let args = match unsafe { CLOSE_STASH.get(&pid_tgid) } {
        Some(args) => FdArgs {
            fd: args.fd,
            _pad: 0,
        },
        None => return Ok(0),
    };
    let _ = CLOSE_STASH.remove(&pid_tgid);

    if result != 0 {
        return Ok(0);
    }

    let zero = unsafe { core::ptr::read_volatile(&0_u64) };
    let event = IoEvent {
        kind: EVENT_CLOSE,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        fd: args.fd,
        bytes: zero,
        latency_ns: zero,
    };
    if EVENTS.output::<IoEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
    Ok(0)
}

macro_rules! dup_programs {
    ($enter:ident, $exit:ident) => {
        #[tracepoint]
        pub fn $enter(ctx: TracePointContext) -> u32 {
            try_sys_enter_fd(&ctx, &DUP_STASH).unwrap_or(0)
        }

        #[tracepoint]
        pub fn $exit(ctx: TracePointContext) -> u32 {
            try_sys_exit_dup(&ctx).unwrap_or(0)
        }
    };
}

dup_programs!(sys_enter_dup, sys_exit_dup);
dup_programs!(sys_enter_dup2, sys_exit_dup2);
dup_programs!(sys_enter_dup3, sys_exit_dup3);

fn try_sys_exit_dup(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let result: i64 = unsafe { ctx.read_at(16)? };
    let args = match unsafe { DUP_STASH.get(&pid_tgid) } {
        Some(args) => FdArgs {
            fd: args.fd,
            _pad: 0,
        },
        None => return Ok(0),
    };
    let _ = DUP_STASH.remove(&pid_tgid);

    if result < 0 {
        return Ok(0);
    }

    let event = FdEvent {
        kind: EVENT_DUP,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        old_fd: args.fd,
        new_fd: result as u32,
        _pad: 0,
    };
    if EVENTS.output::<FdEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
