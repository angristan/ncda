use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::RawTracePoint;
use aya::Ebpf;
use log::{debug, info};
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
        emitted_ns: u64,
    },
    Read {
        pid: u32,
        tid: u32,
        fd: u32,
        bytes: u64,
        latency_ns: u64,
        emitted_ns: u64,
    },
    Write {
        pid: u32,
        tid: u32,
        fd: u32,
        bytes: u64,
        latency_ns: u64,
        emitted_ns: u64,
    },
    Close {
        pid: u32,
        tid: u32,
        fd: u32,
        emitted_ns: u64,
    },
    Dup {
        pid: u32,
        tid: u32,
        old_fd: u32,
        new_fd: u32,
        emitted_ns: u64,
    },
    CloseRange {
        pid: u32,
        tid: u32,
        first_fd: u32,
        last_fd: u32,
        flags: u32,
        emitted_ns: u64,
    },
    ProcessExec {
        pid: u32,
        emitted_ns: u64,
    },
    ProcessExit {
        pid: u32,
        emitted_ns: u64,
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
            total.read_entries += value.read_entries;
            total.write_entries += value.write_entries;
            total.read_exits += value.read_exits;
            total.write_exits += value.write_exits;
            total
        }))
}

/// Load and globally attach the architecture-specific raw syscall decoder.
pub fn load_and_attach(ebpf: &mut Ebpf) -> Result<()> {
    for (program_name, tracepoint_name) in [
        ("sys_enter", "sys_enter"),
        ("sys_exit", "sys_exit"),
        ("sched_process_exec", "sched_process_exec"),
        ("sched_process_exit", "sched_process_exit"),
    ] {
        let program: &mut RawTracePoint = ebpf
            .program_mut(program_name)
            .with_context(|| format!("program {program_name} not found"))?
            .try_into()
            .with_context(|| format!("failed to get program {program_name}"))?;
        program.load()?;
        program.attach(tracepoint_name)?;
        info!("attached {program_name} to raw tracepoint {tracepoint_name}");
    }
    Ok(())
}

/// Read ring-buffer events using epoll readiness instead of periodic polling.
/// The caller detaches all producers before requesting shutdown, allowing one
/// final nonblocking drain to consume every record already in the ring.
pub async fn reader_loop(
    ring_buf: RingBuf<MapData>,
    tx: mpsc::Sender<Vec<BpfEvent>>,
    mut shutdown: watch::Receiver<bool>,
    drops: Arc<ReaderDropCounters>,
) -> Result<()> {
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        tokio::select! {
            result = shutdown.changed() => {
                let batch = drain_ring(async_fd.get_mut(), &drops);
                send_batch(&tx, batch, &drops).await;
                if result.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            ready = async_fd.readable_mut() => {
                let mut guard = ready?;
                let batch = drain_ring(guard.get_inner_mut(), &drops);
                guard.clear_ready();
                drop(guard);
                if !send_batch(&tx, batch, &drops).await {
                    return Ok(());
                }
            }
        }
    }
}

fn drain_ring(ring_buf: &mut RingBuf<MapData>, drops: &ReaderDropCounters) -> Vec<BpfEvent> {
    let mut batch = Vec::with_capacity(256);
    while let Some(item) = ring_buf.next() {
        let data: &[u8] = &item;
        if let Some(event) = parse_event(data) {
            batch.push(event);
        } else {
            drops.record_parse_drop();
        }
    }
    batch
}

async fn send_batch(
    tx: &mpsc::Sender<Vec<BpfEvent>>,
    batch: Vec<BpfEvent>,
    drops: &ReaderDropCounters,
) -> bool {
    if batch.is_empty() {
        return true;
    }

    let batch_len = batch.len();
    if tx.send(batch).await.is_err() {
        drops.record_queue_drops(batch_len);
        return false;
    }
    true
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
        EVENT_CLOSE_RANGE => parse_range_event(data),
        EVENT_PROCESS_EXEC | EVENT_PROCESS_EXIT => parse_process_event(data, kind),
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

    let emitted_ns = u64::from_ne_bytes(data[24..32].try_into().ok()?);
    let fname_start = 32; // after metadata and emission timestamp
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
        emitted_ns,
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
    let emitted_ns = u64::from_ne_bytes(data[32..40].try_into().ok()?);

    match kind {
        EVENT_READ => Some(BpfEvent::Read {
            pid,
            tid,
            fd,
            bytes,
            latency_ns,
            emitted_ns,
        }),
        EVENT_WRITE => Some(BpfEvent::Write {
            pid,
            tid,
            fd,
            bytes,
            latency_ns,
            emitted_ns,
        }),
        EVENT_CLOSE => Some(BpfEvent::Close {
            pid,
            tid,
            fd,
            emitted_ns,
        }),
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
        emitted_ns: u64::from_ne_bytes(data[24..32].try_into().ok()?),
    })
}

fn parse_range_event(data: &[u8]) -> Option<BpfEvent> {
    if data.len() < core::mem::size_of::<RangeEvent>() {
        return None;
    }

    Some(BpfEvent::CloseRange {
        pid: u32::from_ne_bytes(data[4..8].try_into().ok()?),
        tid: u32::from_ne_bytes(data[8..12].try_into().ok()?),
        first_fd: u32::from_ne_bytes(data[12..16].try_into().ok()?),
        last_fd: u32::from_ne_bytes(data[16..20].try_into().ok()?),
        flags: u32::from_ne_bytes(data[20..24].try_into().ok()?),
        emitted_ns: u64::from_ne_bytes(data[24..32].try_into().ok()?),
    })
}

fn parse_process_event(data: &[u8], kind: u32) -> Option<BpfEvent> {
    if data.len() < core::mem::size_of::<ProcessEvent>() {
        return None;
    }
    let pid = u32::from_ne_bytes(data[4..8].try_into().ok()?);
    let emitted_ns = u64::from_ne_bytes(data[8..16].try_into().ok()?);
    match kind {
        EVENT_PROCESS_EXEC => Some(BpfEvent::ProcessExec { pid, emitted_ns }),
        EVENT_PROCESS_EXIT => Some(BpfEvent::ProcessExit { pid, emitted_ns }),
        _ => None,
    }
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

impl Default for FdPathCache {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn on_close_range(&mut self, pid: u32, first_fd: u32, last_fd: u32) {
        self.map
            .retain(|(entry_pid, fd), _| *entry_pid != pid || *fd < first_fd || *fd > last_fd);
    }

    pub fn on_process_reset(&mut self, pid: u32) {
        self.map.retain(|(entry_pid, _), _| *entry_pid != pid);
        self.root_cache.remove(&pid);
    }

    pub fn lookup(&self, pid: u32, fd: u32) -> Option<&str> {
        self.map.get(&(pid, fd)).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Resolve the true file path for a given pid/fd via procfs.
    /// Unresolved relative paths are kept in an explicit diagnostic namespace.
    fn resolve_fd_path(&mut self, pid: u32, fd: u32, dirfd: i32, raw_path: &str) -> String {
        // Try readlink on /proc/pid/fd/fd to get the kernel-resolved path.
        // This works even for relative openat(dirfd, name, ...) calls
        // because the kernel has already resolved the path.
        if let Ok(resolved) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
            if let Some(s) = resolved.to_str() {
                // The kernel appends " (deleted)" for unlinked-but-open files.
                let s = s.trim_end_matches(" (deleted)");
                match classify_pseudo_path(s) {
                    PseudoPath::Ignore => return String::new(),
                    PseudoPath::Memory(path) => return path,
                    PseudoPath::Ordinary if s.starts_with('/') => {
                        let path = self.strip_container_root(pid, s);
                        return normalize_absolute_path(&path);
                    }
                    PseudoPath::Ordinary => {}
                }
            }
        }

        // A cache miss for inherited or pre-existing descriptors has no raw
        // path. Never substitute the process cwd: it describes a directory,
        // not the descriptor that performed the I/O.
        if raw_path.is_empty() {
            return String::new();
        }

        match classify_pseudo_path(raw_path) {
            PseudoPath::Ignore => return String::new(),
            PseudoPath::Memory(path) => return path,
            PseudoPath::Ordinary => {}
        }

        // If the raw path is already absolute, normalize it before aggregation.
        if raw_path.starts_with('/') {
            return normalize_absolute_path(raw_path);
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
                let path = self.strip_container_root(pid, &full_path);
                return normalize_absolute_path(&path);
            }
        }

        // The process or descriptor can disappear before userspace performs
        // procfs resolution. Preserve that activity without presenting a raw
        // basename as if it existed at the filesystem root.
        let raw_path = normalize_relative_path(raw_path);
        if raw_path.is_empty() {
            format!("/[unresolved]/pid-{pid}")
        } else {
            format!("/[unresolved]/pid-{pid}/{raw_path}")
        }
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

#[derive(Debug, PartialEq, Eq)]
enum PseudoPath {
    Ordinary,
    Ignore,
    Memory(String),
}

fn classify_pseudo_path(path: &str) -> PseudoPath {
    let path = path.trim_end_matches(" (deleted)");
    let target = path.strip_prefix('/').unwrap_or(path);
    if target.starts_with("socket:")
        || target.starts_with("pipe:")
        || target.starts_with("anon_inode:")
    {
        return PseudoPath::Ignore;
    }
    if let Some(name) = target.strip_prefix("memfd:") {
        // A memfd name may contain slashes, but it is one kernel object rather
        // than a filesystem hierarchy. Keep it in one safe display component.
        let name = name.replace('/', "∕");
        return PseudoPath::Memory(format!("/[memory]/memfd:{name}"));
    }
    PseudoPath::Ordinary
}

fn normalize_absolute_path(path: &str) -> String {
    let normalized = normalize_relative_path(path);
    if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("/{normalized}")
    }
}

fn normalize_relative_path(path: &str) -> String {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    components.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_event_abi_has_expected_sizes() {
        assert_eq!(core::mem::size_of::<OpenEvent>(), 288);
        assert_eq!(core::mem::size_of::<IoEvent>(), 40);
        assert_eq!(core::mem::size_of::<FdEvent>(), 32);
        assert_eq!(core::mem::size_of::<RangeEvent>(), 32);
        assert_eq!(core::mem::size_of::<ProcessEvent>(), 16);
        assert_eq!(core::mem::size_of::<CaptureStats>(), 56);
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
        let mut open = [0_u8; 288];
        open[0..4].copy_from_slice(&EVENT_OPEN.to_ne_bytes());
        open[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        open[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        open[12..16].copy_from_slice(&9_u32.to_ne_bytes());
        open[16..20].copy_from_slice(&4_u32.to_ne_bytes());
        open[20..24].copy_from_slice(&(-100_i32).to_ne_bytes());
        open[24..32].copy_from_slice(&123_u64.to_ne_bytes());
        open[32..36].copy_from_slice(b"file");
        assert!(matches!(
            parse_event(&open),
            Some(BpfEvent::Open {
                pid: 7,
                tid: 8,
                fd: 9,
                dirfd: -100,
                ref path,
                emitted_ns: 123,
            }) if path == "file"
        ));

        let mut dup = [0_u8; 32];
        dup[0..4].copy_from_slice(&EVENT_DUP.to_ne_bytes());
        dup[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        dup[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        dup[12..16].copy_from_slice(&9_u32.to_ne_bytes());
        dup[16..20].copy_from_slice(&10_u32.to_ne_bytes());
        dup[24..32].copy_from_slice(&456_u64.to_ne_bytes());
        assert!(matches!(
            parse_event(&dup),
            Some(BpfEvent::Dup {
                pid: 7,
                tid: 8,
                old_fd: 9,
                new_fd: 10,
                emitted_ns: 456,
            })
        ));

        let mut range = [0_u8; 32];
        range[0..4].copy_from_slice(&EVENT_CLOSE_RANGE.to_ne_bytes());
        range[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        range[8..12].copy_from_slice(&8_u32.to_ne_bytes());
        range[12..16].copy_from_slice(&9_u32.to_ne_bytes());
        range[16..20].copy_from_slice(&12_u32.to_ne_bytes());
        range[20..24].copy_from_slice(&2_u32.to_ne_bytes());
        range[24..32].copy_from_slice(&789_u64.to_ne_bytes());
        assert!(matches!(
            parse_event(&range),
            Some(BpfEvent::CloseRange {
                pid: 7,
                tid: 8,
                first_fd: 9,
                last_fd: 12,
                flags: 2,
                emitted_ns: 789,
            })
        ));

        let mut process = [0_u8; 16];
        process[0..4].copy_from_slice(&EVENT_PROCESS_EXEC.to_ne_bytes());
        process[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        process[8..16].copy_from_slice(&999_u64.to_ne_bytes());
        assert!(matches!(
            parse_event(&process),
            Some(BpfEvent::ProcessExec {
                pid: 7,
                emitted_ns: 999,
            })
        ));
    }

    #[test]
    fn close_range_and_process_reset_purge_cached_descriptors() {
        let mut cache = FdPathCache::new();
        for fd in 3..=7 {
            cache.store(42, fd, format!("/tmp/{fd}"));
        }
        cache.store(43, 5, "/tmp/other".to_string());

        cache.on_close_range(42, 4, 6);
        assert!(cache.lookup(42, 3).is_some());
        assert!(cache.lookup(42, 4).is_none());
        assert!(cache.lookup(42, 6).is_none());
        assert!(cache.lookup(42, 7).is_some());
        assert!(cache.lookup(43, 5).is_some());

        cache.on_process_reset(42);
        assert!(cache.lookup(42, 3).is_none());
        assert!(cache.lookup(42, 7).is_none());
        assert!(cache.lookup(43, 5).is_some());
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
    fn unresolved_relative_paths_do_not_pollute_root() {
        let mut cache = FdPathCache::new();
        let resolved = cache.resolve(u32::MAX, u32::MAX, libc::AT_FDCWD, "../../b006");

        assert_eq!(resolved, "/[unresolved]/pid-4294967295/b006");
    }

    #[test]
    fn pseudo_descriptors_are_filtered_or_grouped() {
        assert_eq!(classify_pseudo_path("socket:[123]"), PseudoPath::Ignore);
        assert_eq!(classify_pseudo_path("pipe:[123]"), PseudoPath::Ignore);
        assert_eq!(
            classify_pseudo_path("anon_inode:[eventfd]"),
            PseudoPath::Ignore
        );
        assert_eq!(
            classify_pseudo_path("/memfd:sd/executor-state (deleted)"),
            PseudoPath::Memory("/[memory]/memfd:sd∕executor-state".to_string())
        );
    }

    #[test]
    fn filesystem_paths_are_lexically_normalized() {
        assert_eq!(
            normalize_absolute_path("/sys/devices/../bus/./pci"),
            "/sys/bus/pci"
        );
        assert_eq!(normalize_absolute_path("/../../etc/hosts"), "/etc/hosts");
    }

    #[test]
    fn missing_preexisting_descriptor_does_not_resolve_to_cwd() {
        let mut cache = FdPathCache::new();

        assert_eq!(cache.resolve_existing(std::process::id(), u32::MAX), None);
    }

    #[test]
    fn parser_lossily_preserves_non_utf8_paths() {
        let mut open = [0_u8; 288];
        open[0..4].copy_from_slice(&EVENT_OPEN.to_ne_bytes());
        open[16..20].copy_from_slice(&3_u32.to_ne_bytes());
        open[20..24].copy_from_slice(&libc::AT_FDCWD.to_ne_bytes());
        open[32..35].copy_from_slice(&[b'a', 0xff, b'b']);

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
