#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, raw_tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::RawTracePointContext,
};
use ncda_common::*;

#[cfg(bpf_target_arch = "x86_64")]
mod arch {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const CLOSE: i64 = 3;
    pub const PREAD64: i64 = 17;
    pub const PWRITE64: i64 = 18;
    pub const READV: i64 = 19;
    pub const WRITEV: i64 = 20;
    pub const DUP: i64 = 32;
    pub const DUP2: i64 = 33;
    pub const DUP3: i64 = 292;
    pub const FCNTL: i64 = 72;
    pub const CLOSE_RANGE: i64 = 436;
    pub const PREADV: i64 = 295;
    pub const PWRITEV: i64 = 296;
    pub const PREADV2: i64 = 327;
    pub const PWRITEV2: i64 = 328;
    pub const OPENAT: i64 = 257;
    pub const OPENAT2: i64 = 437;
    pub const ARG_REGISTERS: [usize; 3] = [14, 13, 12];
}

#[cfg(bpf_target_arch = "aarch64")]
mod arch {
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const CLOSE: i64 = 57;
    pub const PREAD64: i64 = 67;
    pub const PWRITE64: i64 = 68;
    pub const READV: i64 = 65;
    pub const WRITEV: i64 = 66;
    pub const DUP: i64 = 23;
    // arm64 has no native dup2; libc implements it with dup3.
    pub const DUP2: i64 = -1;
    pub const DUP3: i64 = 24;
    pub const FCNTL: i64 = 25;
    pub const CLOSE_RANGE: i64 = 436;
    pub const PREADV: i64 = 69;
    pub const PWRITEV: i64 = 70;
    pub const PREADV2: i64 = 286;
    pub const PWRITEV2: i64 = 287;
    pub const OPENAT: i64 = 56;
    pub const OPENAT2: i64 = 437;
    pub const ARG_REGISTERS: [usize; 3] = [0, 1, 2];
}

#[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
compile_error!("ncda eBPF supports x86_64 and arm64");

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);
#[map]
static OPEN_STASH: HashMap<u64, OpenArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static IO_STASH: HashMap<u64, RwArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static CLOSE_STASH: HashMap<u64, FdArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static DUP_STASH: HashMap<u64, FdArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static RANGE_STASH: HashMap<u64, RangeArgs> = HashMap::with_max_entries(8192, 0);
#[map]
static SCRATCH: PerCpuArray<OpenArgs> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EVENT_BUF: PerCpuArray<OpenEvent> = PerCpuArray::with_max_entries(1, 0);
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

#[inline(always)]
fn record_io_entry(kind: u32) {
    if let Some(stats) = CAPTURE_STATS.get_ptr_mut(0) {
        unsafe {
            if kind == EVENT_READ {
                (*stats).read_entries += 1;
            } else {
                (*stats).write_entries += 1;
            }
        }
    }
}

#[inline(always)]
fn record_io_exit(kind: u32) {
    if let Some(stats) = CAPTURE_STATS.get_ptr_mut(0) {
        unsafe {
            if kind == EVENT_READ {
                (*stats).read_exits += 1;
            } else {
                (*stats).write_exits += 1;
            }
        }
    }
}

#[inline(always)]
unsafe fn syscall_arg(registers: *const u64, argument: usize) -> u64 {
    let index = arch::ARG_REGISTERS[argument];
    unsafe { bpf_probe_read_kernel(registers.add(index)) }.unwrap_or(0)
}

#[inline(always)]
fn io_kind(syscall: i64) -> Option<u32> {
    match syscall {
        arch::READ | arch::PREAD64 | arch::READV | arch::PREADV | arch::PREADV2 => Some(EVENT_READ),
        arch::WRITE | arch::PWRITE64 | arch::WRITEV | arch::PWRITEV | arch::PWRITEV2 => {
            Some(EVENT_WRITE)
        }
        _ => None,
    }
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn sys_enter(ctx: RawTracePointContext) -> i32 {
    let syscall: i64 = ctx.arg(1);
    let registers = ctx.arg::<usize>(0) as *const u64;
    let pid_tgid = bpf_get_current_pid_tgid();

    if syscall == arch::OPENAT || syscall == arch::OPENAT2 {
        enter_open(registers, pid_tgid);
    } else if let Some(kind) = io_kind(syscall) {
        enter_io(registers, pid_tgid, kind);
    } else if syscall == arch::CLOSE {
        enter_fd(registers, pid_tgid, &CLOSE_STASH);
    } else if syscall == arch::DUP || syscall == arch::DUP2 || syscall == arch::DUP3 {
        enter_fd(registers, pid_tgid, &DUP_STASH);
    } else if syscall == arch::FCNTL {
        enter_fcntl(registers, pid_tgid);
    } else if syscall == arch::CLOSE_RANGE {
        enter_close_range(registers, pid_tgid);
    }
    0
}

#[inline(always)]
fn enter_open(registers: *const u64, pid_tgid: u64) {
    let scratch = match SCRATCH.get_ptr_mut(0) {
        Some(scratch) => scratch,
        None => {
            record_scratch_failure();
            return;
        }
    };
    let args = unsafe { &mut *scratch };
    args.dirfd = unsafe { syscall_arg(registers, 0) } as i32;
    args.fname_len = 0;
    let filename_ptr = unsafe { syscall_arg(registers, 1) };
    if let Ok(filename) =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut args.fname) }
    {
        args.fname_len = filename.len() as u32;
    }
    if OPEN_STASH.insert(&pid_tgid, args, 0).is_err() {
        record_stash_failure();
    }
}

#[inline(always)]
fn enter_io(registers: *const u64, pid_tgid: u64, kind: u32) {
    record_io_entry(kind);
    let args = RwArgs {
        ts: unsafe { bpf_ktime_get_ns() },
        fd: unsafe { syscall_arg(registers, 0) } as u32,
        kind,
    };
    if IO_STASH.insert(&pid_tgid, &args, 0).is_err() {
        record_stash_failure();
    }
}

#[inline(always)]
fn enter_fd(registers: *const u64, pid_tgid: u64, stash: &HashMap<u64, FdArgs>) {
    let args = FdArgs {
        fd: unsafe { syscall_arg(registers, 0) } as u32,
        _pad: 0,
    };
    if stash.insert(&pid_tgid, &args, 0).is_err() {
        record_stash_failure();
    }
}

#[inline(always)]
fn enter_fcntl(registers: *const u64, pid_tgid: u64) {
    const F_DUPFD: u64 = 0;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let command = unsafe { syscall_arg(registers, 1) };
    if command == F_DUPFD || command == F_DUPFD_CLOEXEC {
        enter_fd(registers, pid_tgid, &DUP_STASH);
    }
}

#[inline(always)]
fn enter_close_range(registers: *const u64, pid_tgid: u64) {
    let args = RangeArgs {
        first_fd: unsafe { syscall_arg(registers, 0) } as u32,
        last_fd: unsafe { syscall_arg(registers, 1) } as u32,
        flags: unsafe { syscall_arg(registers, 2) } as u32,
        _pad: 0,
    };
    if RANGE_STASH.insert(&pid_tgid, &args, 0).is_err() {
        record_stash_failure();
    }
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn sys_exit(ctx: RawTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let result: i64 = ctx.arg(1);

    if let Some(args) = unsafe { OPEN_STASH.get(&pid_tgid) } {
        exit_open(pid_tgid, result, args);
        let _ = OPEN_STASH.remove(&pid_tgid);
    } else if let Some(args) = unsafe { IO_STASH.get(&pid_tgid) } {
        let args = RwArgs {
            ts: args.ts,
            fd: args.fd,
            kind: args.kind,
        };
        let _ = IO_STASH.remove(&pid_tgid);
        exit_io(pid_tgid, result, &args);
    } else if let Some(args) = unsafe { CLOSE_STASH.get(&pid_tgid) } {
        let fd = args.fd;
        let _ = CLOSE_STASH.remove(&pid_tgid);
        exit_close(pid_tgid, result, fd);
    } else if let Some(args) = unsafe { DUP_STASH.get(&pid_tgid) } {
        let old_fd = args.fd;
        let _ = DUP_STASH.remove(&pid_tgid);
        exit_dup(pid_tgid, result, old_fd);
    } else if let Some(args) = unsafe { RANGE_STASH.get(&pid_tgid) } {
        let args = RangeArgs {
            first_fd: args.first_fd,
            last_fd: args.last_fd,
            flags: args.flags,
            _pad: 0,
        };
        let _ = RANGE_STASH.remove(&pid_tgid);
        exit_close_range(pid_tgid, result, &args);
    } else {
        // Untracked syscalls intentionally have no stash entry.
    }
    0
}

#[inline(always)]
fn exit_open(pid_tgid: u64, result: i64, args: &OpenArgs) {
    if result < 0 {
        return;
    }
    let buf = match EVENT_BUF.get_ptr_mut(0) {
        Some(buf) => buf,
        None => {
            record_scratch_failure();
            return;
        }
    };
    let event = unsafe { &mut *buf };
    event.kind = EVENT_OPEN;
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.fd = result as u32;
    event.fname_len = args.fname_len;
    event.dirfd = args.dirfd;
    event.emitted_ns = unsafe { bpf_ktime_get_ns() };
    let mut index = 0usize;
    while index < MAX_FNAME_LEN {
        event.fname[index] = args.fname[index];
        index += 1;
    }
    if EVENTS.output::<OpenEvent>(unsafe { &*buf }, 0).is_err() {
        record_ring_drop();
    }
}

#[inline(always)]
fn exit_io(pid_tgid: u64, result: i64, args: &RwArgs) {
    record_io_exit(args.kind);
    let emitted_ns = unsafe { bpf_ktime_get_ns() };
    let event = IoEvent {
        kind: args.kind,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        fd: args.fd,
        result,
        latency_ns: emitted_ns - args.ts,
        emitted_ns,
    };
    if EVENTS.output::<IoEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
}

#[inline(always)]
fn exit_close(pid_tgid: u64, result: i64, fd: u32) {
    if result != 0 {
        return;
    }
    let zero = unsafe { core::ptr::read_volatile(&0_u64) };
    let event = IoEvent {
        kind: EVENT_CLOSE,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        fd,
        result: zero as i64,
        latency_ns: zero,
        emitted_ns: unsafe { bpf_ktime_get_ns() },
    };
    if EVENTS.output::<IoEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
}

#[inline(always)]
fn exit_dup(pid_tgid: u64, result: i64, old_fd: u32) {
    if result < 0 {
        return;
    }
    let event = FdEvent {
        kind: EVENT_DUP,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        old_fd,
        new_fd: result as u32,
        _pad: 0,
        emitted_ns: unsafe { bpf_ktime_get_ns() },
    };
    if EVENTS.output::<FdEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
}

#[inline(always)]
fn exit_close_range(pid_tgid: u64, result: i64, args: &RangeArgs) {
    if result != 0 {
        return;
    }
    let event = RangeEvent {
        kind: EVENT_CLOSE_RANGE,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        first_fd: args.first_fd,
        last_fd: args.last_fd,
        flags: args.flags,
        emitted_ns: unsafe { bpf_ktime_get_ns() },
    };
    if EVENTS.output::<RangeEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
}

#[inline(always)]
fn emit_process_event(kind: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if pid != tid {
        return;
    }
    let event = ProcessEvent {
        kind,
        pid,
        emitted_ns: unsafe { bpf_ktime_get_ns() },
    };
    if EVENTS.output::<ProcessEvent>(&event, 0).is_err() {
        record_ring_drop();
    }
}

#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn sched_process_exec(_ctx: RawTracePointContext) -> i32 {
    emit_process_event(EVENT_PROCESS_EXEC);
    0
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn sched_process_exit(_ctx: RawTracePointContext) -> i32 {
    emit_process_event(EVENT_PROCESS_EXIT);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
