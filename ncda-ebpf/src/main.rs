#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ncda_common::*;

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Ring buffer for sending events to userspace (16 MiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Stash for correlating sys_enter_openat → sys_exit_openat.
/// Key: pid_tgid (u64).  Value: OpenArgs (filename + flags).
#[map]
static OPEN_STASH: HashMap<u64, OpenArgs> = HashMap::with_max_entries(8192, 0);

/// Stash for correlating sys_enter_{read,write} → sys_exit_{read,write}.
/// Key: pid_tgid (u64).  Value: RwArgs (timestamp + fd).
#[map]
static RW_STASH: HashMap<u64, RwArgs> = HashMap::with_max_entries(8192, 0);

/// Per-CPU scratch buffer for constructing OpenArgs values.
/// Avoids putting 264-byte OpenArgs on the 512-byte eBPF stack.
#[map]
static SCRATCH: PerCpuArray<OpenArgs> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch buffer for constructing OpenEvent values before output.
#[map]
static EVENT_BUF: PerCpuArray<OpenEvent> = PerCpuArray::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// sys_enter_openat — capture filename and stash for exit handler
// ---------------------------------------------------------------------------
//
// Tracepoint format (x86_64):
//   offset 8:  __syscall_nr (i32)
//   offset 16: dfd          (u64)
//   offset 24: filename     (u64, user pointer)
//   offset 32: flags        (u64)
//   offset 40: mode         (u64)

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let filename_ptr: u64 = unsafe { ctx.read_at(24)? };
    let flags: u64 = unsafe { ctx.read_at(32)? };

    // Get scratch buffer (per-CPU, avoids stack overflow)
    let scratch = SCRATCH.get_ptr_mut(0).ok_or(1i64)?;
    let args = unsafe { &mut *scratch };
    args.flags = flags as u32;
    args.fname_len = 0;

    // Read filename from user-space pointer into scratch buffer
    match unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut args.fname) } {
        Ok(s) => args.fname_len = s.len() as u32,
        Err(_) => args.fname_len = 0,
    }

    // Stash for sys_exit_openat to pick up
    OPEN_STASH.insert(&pid_tgid, args, 0)?;

    Ok(0)
}

// ---------------------------------------------------------------------------
// sys_exit_openat — emit OpenEvent with fd + path
// ---------------------------------------------------------------------------
//
// Tracepoint format:
//   offset 8:  __syscall_nr (i32)
//   offset 16: ret          (i64) — fd on success, negative errno on failure

#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    match try_sys_exit_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_exit_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret: i64 = unsafe { ctx.read_at(16)? };

    // Look up stashed args from entry
    let stash = match unsafe { OPEN_STASH.get(&pid_tgid) } {
        Some(args) => args,
        None => return Ok(0),
    };

    if ret < 0 {
        // Open failed — clean up stash
        let _ = OPEN_STASH.remove(&pid_tgid);
        return Ok(0);
    }

    let fd = ret as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Construct OpenEvent in per-CPU buffer
    let buf = EVENT_BUF.get_ptr_mut(0).ok_or(1i64)?;
    let event = unsafe { &mut *buf };
    event.kind = EVENT_OPEN;
    event.pid = tgid;
    event.tid = tid;
    event.fd = fd;
    event.fname_len = stash.fname_len;
    event._pad = 0;

    // Copy filename from stash into event buffer.
    // Both pointers are to BPF map memory with known bounds.
    // Use a bounded loop that the verifier can track.
    let src = &stash.fname;
    let dst = &mut event.fname;
    let mut i = 0usize;
    while i < MAX_FNAME_LEN {
        dst[i] = src[i];
        i += 1;
    }

    // Output event to ring buffer
    EVENTS.output::<OpenEvent>(unsafe { &*buf }, 0).ok();

    // Clean up stash
    let _ = OPEN_STASH.remove(&pid_tgid);

    Ok(0)
}

// ---------------------------------------------------------------------------
// sys_enter_read — stash fd + timestamp for latency computation
// ---------------------------------------------------------------------------
//
// Tracepoint format:
//   offset 16: fd    (u64)
//   offset 24: buf   (u64, user pointer)
//   offset 32: count (u64)

#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match try_sys_enter_rw(&ctx, true) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match try_sys_enter_rw(&ctx, false) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_rw(ctx: &TracePointContext, _is_read: bool) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let ts = unsafe { bpf_ktime_get_ns() };

    // RwArgs is 16 bytes — fits on the 512-byte stack
    let args = RwArgs {
        ts,
        fd: fd as u32,
        _pad: 0,
    };
    RW_STASH.insert(&pid_tgid, &args, 0)?;

    Ok(0)
}

// ---------------------------------------------------------------------------
// sys_exit_read — emit ReadEvent with bytes + latency
// ---------------------------------------------------------------------------
//
// Tracepoint format:
//   offset 16: ret (i64) — bytes read, or negative errno

#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match try_sys_exit_rw(&ctx, EVENT_READ) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match try_sys_exit_rw(&ctx, EVENT_WRITE) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_exit_rw(ctx: &TracePointContext, kind: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ret: i64 = unsafe { ctx.read_at(16)? };

    // Look up entry stash
    let args = match unsafe { RW_STASH.get(&pid_tgid) } {
        Some(a) => RwArgs {
            ts: a.ts,
            fd: a.fd,
            _pad: 0,
        },
        None => return Ok(0),
    };
    let _ = RW_STASH.remove(&pid_tgid);

    if ret <= 0 {
        return Ok(0);
    }

    let latency_ns = unsafe { bpf_ktime_get_ns() } - args.ts;
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // IoEvent is 32 bytes — fits on the stack
    let event = IoEvent {
        kind,
        pid: tgid,
        tid,
        fd: args.fd,
        bytes: ret as u64,
        latency_ns,
    };
    EVENTS.output::<IoEvent>(&event, 0).ok();

    Ok(0)
}

// ---------------------------------------------------------------------------
// sys_enter_close — emit CloseEvent
// ---------------------------------------------------------------------------
//
// Tracepoint format:
//   offset 16: fd (u64)

#[tracepoint]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    match try_sys_enter_close(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_close(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: u64 = unsafe { ctx.read_at(16)? };
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let event = IoEvent {
        kind: EVENT_CLOSE,
        pid: tgid,
        tid,
        fd: fd as u32,
        bytes: 0,
        latency_ns: 0,
    };
    EVENTS.output::<IoEvent>(&event, 0).ok();

    Ok(0)
}

// ---------------------------------------------------------------------------
// Required boilerplate
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
