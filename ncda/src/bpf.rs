use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};

use ncda_common::*;

/// Parsed event from the eBPF ring buffer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BpfEvent {
    Open {
        pid: u32,
        tid: u32,
        fd: u32,
        dirfd: i32,
        path: String,
    },
    Read {
        pid: u32,
        tid: u32,
        fd: u32,
        bytes: u64,
        latency_ns: u64,
    },
    Write {
        pid: u32,
        tid: u32,
        fd: u32,
        bytes: u64,
        latency_ns: u64,
    },
    Close {
        pid: u32,
        tid: u32,
        fd: u32,
    },
    Dup {
        pid: u32,
        tid: u32,
        old_fd: u32,
        new_fd: u32,
    },
}

/// Lock-free counters updated by the ring-buffer reader.
#[derive(Default)]
pub struct ReaderDropCounters {
    parse_drops: AtomicU64,
    queue_drops: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReaderDropSnapshot {
    pub parse_drops: u64,
    pub queue_drops: u64,
}

impl ReaderDropCounters {
    pub fn snapshot(&self) -> ReaderDropSnapshot {
        ReaderDropSnapshot {
            parse_drops: self.parse_drops.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
        }
    }

    fn record_parse_drop(&self) {
        self.parse_drops.fetch_add(1, Ordering::Relaxed);
    }

    fn record_queue_drops(&self, count: usize) {
        self.queue_drops.fetch_add(count as u64, Ordering::Relaxed);
    }
}

/// Sum the kernel's per-CPU capture failure counters.
pub fn capture_stats(map: &PerCpuArray<MapData, CaptureStats>) -> Result<CaptureStats> {
    let values = map.get(&0, 0)?;
    Ok(values
        .iter()
        .fold(CaptureStats::default(), |mut total, value| {
            total.ring_output_drops += value.ring_output_drops;
            total.stash_update_failures += value.stash_update_failures;
            total.scratch_failures += value.scratch_failures;
            total
        }))
}

#[derive(Clone, Copy)]
struct TracepointSpec {
    program: &'static str,
    tracepoint: &'static str,
}

macro_rules! tracepoint_spec {
    ($name:literal) => {
        TracepointSpec {
            program: $name,
            tracepoint: $name,
        }
    };
}

const TRACEPOINTS: &[TracepointSpec] = &[
    tracepoint_spec!("sys_enter_openat"),
    tracepoint_spec!("sys_exit_openat"),
    tracepoint_spec!("sys_enter_openat2"),
    tracepoint_spec!("sys_exit_openat2"),
    tracepoint_spec!("sys_enter_read"),
    tracepoint_spec!("sys_exit_read"),
    tracepoint_spec!("sys_enter_write"),
    tracepoint_spec!("sys_exit_write"),
    tracepoint_spec!("sys_enter_pread64"),
    tracepoint_spec!("sys_exit_pread64"),
    tracepoint_spec!("sys_enter_pwrite64"),
    tracepoint_spec!("sys_exit_pwrite64"),
    tracepoint_spec!("sys_enter_readv"),
    tracepoint_spec!("sys_exit_readv"),
    tracepoint_spec!("sys_enter_writev"),
    tracepoint_spec!("sys_exit_writev"),
    tracepoint_spec!("sys_enter_close"),
    tracepoint_spec!("sys_exit_close"),
    tracepoint_spec!("sys_enter_dup"),
    tracepoint_spec!("sys_exit_dup"),
    tracepoint_spec!("sys_enter_dup2"),
    tracepoint_spec!("sys_exit_dup2"),
    tracepoint_spec!("sys_enter_dup3"),
    tracepoint_spec!("sys_exit_dup3"),
];

/// Load the eBPF programs and attach to architecture-neutral named syscall
/// tracepoints. Linux exposes syscall arguments as normalized eight-byte
/// fields on both x86_64 and arm64; validate that contract before loading.
pub fn load_and_attach(ebpf: &mut Ebpf) -> Result<()> {
    let mut attached = 0usize;
    for spec in TRACEPOINTS {
        if let Err(error) = validate_tracepoint_layout(spec.tracepoint) {
            let optional_dup2 = cfg!(target_arch = "aarch64")
                && spec.tracepoint.ends_with("dup2")
                && error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                });
            if optional_dup2 {
                warn!(
                    "{} is unavailable on arm64; dup3 still provides equivalent coverage",
                    spec.tracepoint
                );
                continue;
            }
            return Err(error);
        }

        let program: &mut TracePoint = ebpf
            .program_mut(spec.program)
            .with_context(|| format!("program {} not found", spec.program))?
            .try_into()
            .with_context(|| format!("failed to get program {}", spec.program))?;
        program.load()?;
        program.attach("syscalls", spec.tracepoint)?;
        attached += 1;
        info!("attached {} to syscalls/{}", spec.program, spec.tracepoint);
    }
    info!("attached {attached} portable syscall tracepoints");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceField {
    name: String,
    offset: usize,
    size: usize,
}

fn validate_tracepoint_layout(tracepoint: &str) -> Result<()> {
    let format = read_tracepoint_format(tracepoint)
        .with_context(|| format!("read format for syscalls/{tracepoint}"))?;
    validate_tracepoint_format(tracepoint, &format)
}

fn read_tracepoint_format(tracepoint: &str) -> std::io::Result<String> {
    let mut last_error = None;
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = format!("{root}/events/syscalls/{tracepoint}/format");
        match std::fs::read_to_string(path) {
            Ok(format) => return Ok(format),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)))
}

fn validate_tracepoint_format(tracepoint: &str, format: &str) -> Result<()> {
    let fields = parse_tracepoint_fields(format);
    require_trace_field(tracepoint, &fields, "__syscall_nr", 8, 4)?;

    if tracepoint.starts_with("sys_exit_") {
        require_trace_field(tracepoint, &fields, "ret", 16, 8)?;
    } else {
        require_field_at(tracepoint, &fields, 16, 8)?;
        if tracepoint == "sys_enter_openat" || tracepoint == "sys_enter_openat2" {
            require_field_at(tracepoint, &fields, 24, 8)?;
        }
    }
    Ok(())
}

fn parse_tracepoint_fields(format: &str) -> Vec<TraceField> {
    format
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let mut parts = line.strip_prefix("field:")?.split(';');
            let declaration = parts.next()?.trim();
            let offset = parts
                .find_map(|part| part.trim().strip_prefix("offset:"))?
                .parse()
                .ok()?;
            let size = line
                .split(';')
                .find_map(|part| part.trim().strip_prefix("size:"))?
                .parse()
                .ok()?;
            let name = declaration
                .split_whitespace()
                .last()?
                .trim_start_matches('*')
                .split('[')
                .next()?
                .to_string();
            Some(TraceField { name, offset, size })
        })
        .collect()
}

fn require_trace_field(
    tracepoint: &str,
    fields: &[TraceField],
    name: &str,
    offset: usize,
    size: usize,
) -> Result<()> {
    if fields
        .iter()
        .any(|field| field.name == name && field.offset == offset && field.size == size)
    {
        return Ok(());
    }
    anyhow::bail!(
        "syscalls/{tracepoint} has incompatible field {name}; expected offset {offset}, size {size}"
    )
}

fn require_field_at(
    tracepoint: &str,
    fields: &[TraceField],
    offset: usize,
    size: usize,
) -> Result<()> {
    if fields
        .iter()
        .any(|field| field.offset == offset && field.size == size)
    {
        return Ok(());
    }
    anyhow::bail!("syscalls/{tracepoint} has no syscall argument at offset {offset}, size {size}")
}

/// Read events from the ring buffer and send parsed events over a channel.
/// This runs as a tokio task using epoll-based async notification.
#[allow(dead_code)]
pub async fn reader_loop(
    ring_buf: RingBuf<MapData>,
    tx: mpsc::Sender<Vec<BpfEvent>>,
) -> Result<()> {
    // Wrap in AsyncFd for epoll-based notification.
    // RingBuf implements AsRawFd so AsyncFd can poll it.
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        // Wait for data to be available
        let mut guard = async_fd.readable_mut().await?;
        let rb = guard.get_inner_mut();

        let mut batch = Vec::with_capacity(256);

        // Drain all available events
        while let Some(item) = rb.next() {
            let data: &[u8] = &item;
            if let Some(event) = parse_event(data) {
                batch.push(event);
            }
        }

        guard.clear_ready();

        if !batch.is_empty() {
            if tx.send(batch).await.is_err() {
                break; // receiver dropped
            }
        }
    }

    Ok(())
}

/// Polling-based reader for environments where AsyncFd doesn't work.
pub async fn reader_loop_polling(
    mut ring_buf: RingBuf<MapData>,
    tx: mpsc::Sender<Vec<BpfEvent>>,
    mut shutdown: watch::Receiver<bool>,
    drops: Arc<ReaderDropCounters>,
) -> Result<()> {
    loop {
        let mut batch = Vec::with_capacity(256);

        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if let Some(event) = parse_event(data) {
                batch.push(event);
            } else {
                drops.record_parse_drop();
            }
        }

        if !batch.is_empty() {
            let batch_len = batch.len();
            if tx.send(batch).await.is_err() {
                drops.record_queue_drops(batch_len);
                return Ok(());
            }
        }

        // The caller detaches all producers before setting shutdown, so this
        // drain observes every record that reached the ring buffer.
        if *shutdown.borrow() {
            return Ok(());
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            result = shutdown.changed() => {
                if result.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

/// Parse raw bytes from the ring buffer into a BpfEvent.
fn parse_event(data: &[u8]) -> Option<BpfEvent> {
    if data.len() < 4 {
        return None;
    }

    let kind = u32::from_ne_bytes(data[0..4].try_into().ok()?);

    match kind {
        EVENT_OPEN => parse_open_event(data),
        EVENT_READ => parse_io_event(data, EVENT_READ),
        EVENT_WRITE => parse_io_event(data, EVENT_WRITE),
        EVENT_CLOSE => parse_io_event(data, EVENT_CLOSE),
        EVENT_DUP => parse_fd_event(data),
        _ => {
            debug!("unknown event kind: {kind}");
            None
        }
    }
}

fn parse_open_event(data: &[u8]) -> Option<BpfEvent> {
    if data.len() < core::mem::size_of::<OpenEvent>() {
        return None;
    }

    let _kind = u32::from_ne_bytes(data[0..4].try_into().ok()?);
    let pid = u32::from_ne_bytes(data[4..8].try_into().ok()?);
    let tid = u32::from_ne_bytes(data[8..12].try_into().ok()?);
    let fd = u32::from_ne_bytes(data[12..16].try_into().ok()?);
    let fname_len = u32::from_ne_bytes(data[16..20].try_into().ok()?);
    let dirfd = i32::from_ne_bytes(data[20..24].try_into().ok()?);

    let fname_start = 24; // after kind, pid, tid, fd, fname_len, dirfd
    let fname_end = fname_start + (fname_len as usize).min(MAX_FNAME_LEN);
    let fname_bytes = &data[fname_start..fname_end.min(data.len())];

    // The filename may be null-terminated
    let path = String::from_utf8_lossy(fname_bytes)
        .trim_end_matches('\0')
        .to_string();

    Some(BpfEvent::Open {
        pid,
        tid,
        fd,
        dirfd,
        path,
    })
}

fn parse_io_event(data: &[u8], kind: u32) -> Option<BpfEvent> {
    if data.len() < core::mem::size_of::<IoEvent>() {
        return None;
    }

    let pid = u32::from_ne_bytes(data[4..8].try_into().ok()?);
    let tid = u32::from_ne_bytes(data[8..12].try_into().ok()?);
    let fd = u32::from_ne_bytes(data[12..16].try_into().ok()?);
    let bytes = u64::from_ne_bytes(data[16..24].try_into().ok()?);
    let latency_ns = u64::from_ne_bytes(data[24..32].try_into().ok()?);

    match kind {
        EVENT_READ => Some(BpfEvent::Read {
            pid,
            tid,
            fd,
            bytes,
            latency_ns,
        }),
        EVENT_WRITE => Some(BpfEvent::Write {
            pid,
            tid,
            fd,
            bytes,
            latency_ns,
        }),
        EVENT_CLOSE => Some(BpfEvent::Close { pid, tid, fd }),
        _ => None,
    }
}

fn parse_fd_event(data: &[u8]) -> Option<BpfEvent> {
    if data.len() < core::mem::size_of::<FdEvent>() {
        return None;
    }

    Some(BpfEvent::Dup {
        pid: u32::from_ne_bytes(data[4..8].try_into().ok()?),
        tid: u32::from_ne_bytes(data[8..12].try_into().ok()?),
        old_fd: u32::from_ne_bytes(data[12..16].try_into().ok()?),
        new_fd: u32::from_ne_bytes(data[16..20].try_into().ok()?),
    })
}

/// Fd-to-path cache maintained in userspace.
/// Maps (pid, fd) → path string.
///
/// When a file is opened, we resolve the raw eBPF-captured filename to the
/// actual file path via `/proc/<pid>/fd/<fd>`. This handles relative paths
/// from `openat(dirfd, "name", ...)` and gives full paths for container
/// processes. For containers, the overlay prefix is stripped using
/// `/proc/<pid>/root` so paths appear as the container sees them.
pub struct FdPathCache {
    map: HashMap<(u32, u32), String>,
    /// Cache of /proc/<pid>/root for container path resolution.
    /// `None` means the process root is `/` (not containerised).
    root_cache: HashMap<u32, Option<String>>,
}

impl FdPathCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            root_cache: HashMap::new(),
        }
    }

    /// Resolve the raw eBPF-captured path via procfs and return it.
    /// Does **not** store the result — call [`store`] afterwards.
    pub fn resolve(&mut self, pid: u32, fd: u32, dirfd: i32, raw_path: &str) -> String {
        self.resolve_fd_path(pid, fd, dirfd, raw_path)
    }

    /// Resolve an inherited or pre-existing descriptor on a cache miss.
    pub fn resolve_existing(&mut self, pid: u32, fd: u32) -> Option<String> {
        let path = self.resolve_fd_path(pid, fd, libc::AT_FDCWD, "");
        (!path.is_empty()).then_some(path)
    }

    /// Store the final (possibly container-prefixed) path for a pid/fd.
    pub fn store(&mut self, pid: u32, fd: u32, path: String) {
        self.map.insert((pid, fd), path);
    }

    pub fn on_close(&mut self, pid: u32, fd: u32) {
        self.map.remove(&(pid, fd));
    }

    pub fn lookup(&self, pid: u32, fd: u32) -> Option<&str> {
        self.map.get(&(pid, fd)).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Resolve the true file path for a given pid/fd via procfs.
    /// Falls back to the raw eBPF-captured path if resolution fails.
    fn resolve_fd_path(&mut self, pid: u32, fd: u32, dirfd: i32, raw_path: &str) -> String {
        // Try readlink on /proc/pid/fd/fd to get the kernel-resolved path.
        // This works even for relative openat(dirfd, name, ...) calls
        // because the kernel has already resolved the path.
        if let Ok(resolved) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
            if let Some(s) = resolved.to_str() {
                // The kernel appends " (deleted)" for unlinked-but-open files
                let s = s.trim_end_matches(" (deleted)");
                // Only use absolute paths; skip pipes, sockets, anon_inode, etc.
                if s.starts_with('/') {
                    return self.strip_container_root(pid, s);
                }
            }
        }

        // If the raw path is already absolute, use it as-is
        if raw_path.starts_with('/') {
            return raw_path.to_string();
        }

        // For relative paths where /proc/pid/fd failed (fd already closed),
        // resolve from cwd for AT_FDCWD or from the actual directory FD.
        let base = if dirfd == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{pid}/cwd"))
        } else {
            std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}"))
        };
        if let Ok(base) = base {
            if let Some(base) = base.to_str() {
                let full_path = format!("{base}/{raw_path}");
                return self.strip_container_root(pid, &full_path);
            }
        }

        // Last resort: return the raw path as captured by eBPF.
        raw_path.to_string()
    }

    /// Strip the container's root filesystem prefix from a host-side path.
    ///
    /// For example, if `/proc/<pid>/root` points to
    /// `/var/lib/docker/overlay2/<hash>/merged`, a host path of
    /// `/var/lib/docker/overlay2/<hash>/merged/var/www/html/index.php`
    /// becomes `/var/www/html/index.php`.
    fn strip_container_root(&mut self, pid: u32, host_path: &str) -> String {
        let root = self.root_cache.entry(pid).or_insert_with(|| {
            std::fs::read_link(format!("/proc/{pid}/root"))
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .filter(|r| r != "/")
        });

        if let Some(root_str) = root {
            if let Some(stripped) = host_path.strip_prefix(root_str.as_str()) {
                return if stripped.is_empty() {
                    "/".to_string()
                } else {
                    stripped.to_string()
                };
            }
        }

        host_path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_event_abi_has_expected_sizes() {
        assert_eq!(core::mem::size_of::<OpenEvent>(), 280);
        assert_eq!(core::mem::size_of::<IoEvent>(), 32);
        assert_eq!(core::mem::size_of::<FdEvent>(), 24);
        assert_eq!(core::mem::size_of::<CaptureStats>(), 24);
    }

    #[test]
    fn reader_drop_snapshot_tracks_each_loss_class() {
        let counters = ReaderDropCounters::default();
        counters.record_parse_drop();
        counters.record_queue_drops(3);

        assert_eq!(
            counters.snapshot(),
            ReaderDropSnapshot {
                parse_drops: 1,
                queue_drops: 3,
            }
        );
    }

    #[test]
    fn malformed_records_are_rejected() {
        assert!(parse_event(&[0; 3]).is_none());

        let mut unknown = [0_u8; 32];
        unknown[0..4].copy_from_slice(&99_u32.to_ne_bytes());
        assert!(parse_event(&unknown).is_none());
    }

    #[test]
    fn parser_preserves_open_dirfd_and_dup_fds() {
        let mut open = [0_u8; 280];
        open[0..4].copy_from_slice(&EVENT_OPEN.to_ne_bytes());
        open[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        open[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        open[12..16].copy_from_slice(&9_u32.to_ne_bytes());
        open[16..20].copy_from_slice(&4_u32.to_ne_bytes());
        open[20..24].copy_from_slice(&(-100_i32).to_ne_bytes());
        open[24..28].copy_from_slice(b"file");
        assert!(matches!(
            parse_event(&open),
            Some(BpfEvent::Open {
                pid: 7,
                tid: 8,
                fd: 9,
                dirfd: -100,
                ref path,
            }) if path == "file"
        ));

        let mut dup = [0_u8; 24];
        dup[0..4].copy_from_slice(&EVENT_DUP.to_ne_bytes());
        dup[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        dup[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        dup[12..16].copy_from_slice(&9_u32.to_ne_bytes());
        dup[16..20].copy_from_slice(&10_u32.to_ne_bytes());
        assert!(matches!(
            parse_event(&dup),
            Some(BpfEvent::Dup {
                pid: 7,
                tid: 8,
                old_fd: 9,
                new_fd: 10,
            })
        ));
    }

    #[test]
    fn relative_fallback_uses_directory_fd() {
        use std::os::fd::AsRawFd;

        let directory = std::fs::File::open("/tmp").unwrap();
        let mut cache = FdPathCache::new();
        let resolved = cache.resolve(std::process::id(), u32::MAX, directory.as_raw_fd(), "child");

        assert_eq!(resolved, "/tmp/child");
    }

    #[test]
    fn tracepoint_layout_validation_accepts_normalized_64_bit_fields() {
        let enter = "\
field:unsigned short common_type; offset:0; size:2; signed:0;\n\
field:int __syscall_nr; offset:8; size:4; signed:1;\n\
field:int dfd; offset:16; size:8; signed:0;\n\
field:const char * filename; offset:24; size:8; signed:0;\n";
        validate_tracepoint_format("sys_enter_openat", enter).unwrap();

        let exit = "\
field:unsigned short common_type; offset:0; size:2; signed:0;\n\
field:int __syscall_nr; offset:8; size:4; signed:1;\n\
field:long ret; offset:16; size:8; signed:1;\n";
        validate_tracepoint_format("sys_exit_openat", exit).unwrap();
    }

    #[test]
    fn tracepoint_layout_validation_rejects_offset_drift() {
        let format = "\
field:int __syscall_nr; offset:8; size:4; signed:1;\n\
field:int dfd; offset:12; size:8; signed:0;\n\
field:const char * filename; offset:20; size:8; signed:0;\n";
        let error = validate_tracepoint_format("sys_enter_openat", format).unwrap_err();
        assert!(error.to_string().contains("offset 16"));
    }

    #[test]
    fn parser_lossily_preserves_non_utf8_paths() {
        let mut open = [0_u8; 280];
        open[0..4].copy_from_slice(&EVENT_OPEN.to_ne_bytes());
        open[16..20].copy_from_slice(&3_u32.to_ne_bytes());
        open[20..24].copy_from_slice(&libc::AT_FDCWD.to_ne_bytes());
        open[24..27].copy_from_slice(&[b'a', 0xff, b'b']);

        assert!(matches!(
            parse_event(&open),
            Some(BpfEvent::Open { ref path, .. }) if path == "a�b"
        ));
    }

    #[test]
    fn preexisting_descriptor_resolves_on_cache_miss() {
        use std::os::fd::AsRawFd;

        let file = std::fs::File::open("/dev/null").unwrap();
        let mut cache = FdPathCache::new();
        let resolved = cache
            .resolve_existing(std::process::id(), file.as_raw_fd() as u32)
            .unwrap();

        assert_eq!(resolved, "/dev/null");
    }
}
