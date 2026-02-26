use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{debug, info};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use ncda_common::*;

/// Parsed event from the eBPF ring buffer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BpfEvent {
    Open {
        pid: u32,
        tid: u32,
        fd: u32,
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
}

/// Load the eBPF programs and attach to tracepoints.
pub fn load_and_attach(ebpf: &mut Ebpf) -> Result<()> {
    // Attach tracepoints for syscall enter/exit
    let tracepoints = [
        ("sys_enter_openat", "syscalls", "sys_enter_openat"),
        ("sys_exit_openat", "syscalls", "sys_exit_openat"),
        ("sys_enter_read", "syscalls", "sys_enter_read"),
        ("sys_exit_read", "syscalls", "sys_exit_read"),
        ("sys_enter_write", "syscalls", "sys_enter_write"),
        ("sys_exit_write", "syscalls", "sys_exit_write"),
        ("sys_enter_close", "syscalls", "sys_enter_close"),
    ];

    for (prog_name, category, tp_name) in &tracepoints {
        let program: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .unwrap()
            .try_into()
            .with_context(|| format!("failed to get program {prog_name}"))?;
        program.load()?;
        program.attach(category, tp_name)?;
        info!("attached {prog_name} to {category}/{tp_name}");
    }

    Ok(())
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
) -> Result<()> {
    loop {
        let mut batch = Vec::with_capacity(256);

        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if let Some(event) = parse_event(data) {
                batch.push(event);
            }
        }

        if !batch.is_empty() {
            if tx.send(batch).await.is_err() {
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(())
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

    let fname_start = 24; // after kind, pid, tid, fd, fname_len, _pad
    let fname_end = fname_start + (fname_len as usize).min(MAX_FNAME_LEN);
    let fname_bytes = &data[fname_start..fname_end.min(data.len())];

    // The filename may be null-terminated
    let path = core::str::from_utf8(fname_bytes)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    Some(BpfEvent::Open { pid, tid, fd, path })
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
    pub fn resolve(&mut self, pid: u32, fd: u32, raw_path: &str) -> String {
        self.resolve_fd_path(pid, fd, raw_path)
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
    fn resolve_fd_path(&mut self, pid: u32, fd: u32, raw_path: &str) -> String {
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
        // try to prepend the process working directory
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
            if let Some(cwd_str) = cwd.to_str() {
                let full_path = format!("{cwd_str}/{raw_path}");
                return self.strip_container_root(pid, &full_path);
            }
        }

        // Last resort: return the raw path as captured by eBPF
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
