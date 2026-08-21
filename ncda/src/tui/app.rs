use std::collections::HashSet;
use std::time::Duration;

use crate::bpf::{BpfEvent, FdPathCache};
use crate::container::ContainerResolver;
use crate::model::{FileTree, OpKind, SortBy};
use crate::process::{ProcessSort, ProcessTable};
use crate::rate::{EventLog, RateTracker};
use crate::tui::filter::FilterQuery;

/// Shared state updated by the aggregator task, read by the TUI.
pub struct AppState {
    pub tree: FileTree,
    pub fd_cache: FdPathCache,
    pub containers: ContainerResolver,
    pub process_table: ProcessTable,
    pub event_log: EventLog,
    pub global_rate: RateTracker,
    pub total_events: u64,
    pub dropped_events: u64,
    /// Paths to exclude from tracking.
    pub exclude_prefixes: Vec<String>,
}

impl AppState {
    pub fn new(rate_window: Duration, exclude_prefixes: Vec<String>) -> Self {
        Self {
            tree: FileTree::new(),
            fd_cache: FdPathCache::new(),
            containers: ContainerResolver::new(),
            process_table: ProcessTable::new(),
            event_log: EventLog::new(rate_window),
            global_rate: RateTracker::new(rate_window),
            total_events: 0,
            dropped_events: 0,
            exclude_prefixes,
        }
    }

    /// Ingest a batch of BPF events into the state.
    pub fn ingest(&mut self, events: Vec<BpfEvent>) {
        for event in events {
            self.total_events += 1;
            match event {
                BpfEvent::Open {
                    pid,
                    tid: _,
                    fd,
                    dirfd,
                    path,
                    emitted_ns: _,
                } => {
                    // Resolve the raw eBPF path via /proc/pid/fd/fd,
                    // giving us the full absolute path even for relative
                    // openat() calls and container processes.
                    let mut resolved = self.fd_cache.resolve(pid, fd, dirfd, &path);
                    if resolved.is_empty() {
                        continue;
                    }

                    // Prefix with [container_name] for containerised processes
                    // so they appear grouped in the tree.
                    if let Some(name) = self.containers.resolve(pid) {
                        if resolved.starts_with('/') {
                            resolved = format!("/[{name}]{resolved}");
                        } else {
                            resolved = format!("/[{name}]/{resolved}");
                        }
                    }

                    // Store the final path so Read/Write/Close reuse it.
                    self.fd_cache.store(pid, fd, resolved.clone());

                    if self.is_excluded(&resolved) {
                        continue;
                    }
                    self.tree.record(&resolved, pid, OpKind::Open, 0, 0);
                    self.record_process(pid, OpKind::Open, 0, 0);
                }
                BpfEvent::Read {
                    pid,
                    tid: _,
                    fd,
                    bytes,
                    latency_ns,
                    emitted_ns: _,
                } => {
                    if let Some(path) = self.resolve_io_path(pid, fd) {
                        if self.is_excluded(&path) {
                            continue;
                        }
                        self.tree
                            .record(&path, pid, OpKind::Read, bytes, latency_ns);
                        self.record_process(pid, OpKind::Read, bytes, latency_ns);
                        self.global_rate.record(bytes);
                        self.event_log.record(path, pid, bytes);
                    }
                }
                BpfEvent::Write {
                    pid,
                    tid: _,
                    fd,
                    bytes,
                    latency_ns,
                    emitted_ns: _,
                } => {
                    if let Some(path) = self.resolve_io_path(pid, fd) {
                        if self.is_excluded(&path) {
                            continue;
                        }
                        self.tree
                            .record(&path, pid, OpKind::Write, bytes, latency_ns);
                        self.record_process(pid, OpKind::Write, bytes, latency_ns);
                        self.global_rate.record(bytes);
                        self.event_log.record(path, pid, bytes);
                    }
                }
                BpfEvent::Close {
                    pid,
                    tid: _,
                    fd,
                    emitted_ns: _,
                } => {
                    if let Some(path) = self.fd_cache.lookup(pid, fd) {
                        let path = path.to_string();
                        if !self.is_excluded(&path) {
                            self.tree.record(&path, pid, OpKind::Close, 0, 0);
                            self.record_process(pid, OpKind::Close, 0, 0);
                        }
                    }
                    self.fd_cache.on_close(pid, fd);
                }
                BpfEvent::Dup {
                    pid,
                    tid: _,
                    old_fd,
                    new_fd,
                    emitted_ns: _,
                } => {
                    if let Some(path) = self.resolve_io_path(pid, old_fd) {
                        self.fd_cache.store(pid, new_fd, path);
                    }
                }
            }
        }
    }

    fn record_process(&mut self, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        let container = self.containers.resolve(pid).map(str::to_string);
        self.process_table
            .record_with_context(pid, container.as_deref(), op, bytes, latency_ns);
    }

    fn resolve_io_path(&mut self, pid: u32, fd: u32) -> Option<String> {
        if let Some(path) = self.fd_cache.lookup(pid, fd) {
            return Some(path.to_string());
        }

        let mut resolved = self.fd_cache.resolve_existing(pid, fd)?;
        if let Some(name) = self.containers.resolve(pid) {
            if resolved.starts_with('/') {
                resolved = format!("/[{name}]{resolved}");
            } else {
                resolved = format!("/[{name}]/{resolved}");
            }
        }
        self.fd_cache.store(pid, fd, resolved.clone());
        Some(resolved)
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    pub fn reset(&mut self) {
        self.tree.reset();
        self.process_table.reset();
        self.event_log.reset();
        self.global_rate.reset();
        self.total_events = 0;
        self.dropped_events = 0;
    }
}

/// View mode for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Flat,
    Tree,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneFocus {
    Files,
    Processes,
}

/// TUI view state — not shared, owned by the render loop.
#[allow(dead_code)]
pub struct ViewState {
    pub mode: ViewMode,
    /// Current directory path components (flat mode navigation).
    pub cwd: Vec<String>,
    pub cursor: usize,
    pub scroll_offset: usize,
    /// Expanded paths in tree mode.
    pub expanded: HashSet<Vec<String>>,
    pub sort_by: SortBy,
    pub sort_desc: bool,
    pub show_processes: bool,
    pub focus: PaneFocus,
    pub process_cursor: usize,
    pub selected_process: Option<u32>,
    pub process_sort: ProcessSort,
    pub process_sort_desc: bool,
    pub show_help: bool,
    pub filter: FilterQuery,
    pub filter_input: Option<String>,
    pub filter_error: Option<String>,
}

impl Default for ViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState {
    pub fn new() -> Self {
        Self {
            mode: ViewMode::Flat,
            cwd: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            expanded: HashSet::new(),
            sort_by: SortBy::TotalBytes,
            sort_desc: true,
            show_processes: false,
            focus: PaneFocus::Files,
            process_cursor: 0,
            selected_process: None,
            process_sort: ProcessSort::TotalBytes,
            process_sort_desc: true,
            show_help: false,
            filter: FilterQuery::default(),
            filter_input: None,
            filter_error: None,
        }
    }

    pub fn reconcile_process_selection(&mut self, pids: &[u32]) {
        if pids.is_empty() {
            self.process_cursor = 0;
            self.selected_process = None;
            return;
        }
        if let Some(selected) = self.selected_process {
            if let Some(index) = pids.iter().position(|pid| *pid == selected) {
                self.process_cursor = index;
                return;
            }
        }
        self.process_cursor = self.process_cursor.min(pids.len() - 1);
        self.selected_process = Some(pids[self.process_cursor]);
    }

    /// Full path string for the current directory.
    pub fn cwd_path(&self) -> String {
        if self.cwd.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.cwd.join("/"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_descriptor_open_is_not_aggregated() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = u32::MAX;
        state.ingest(vec![BpfEvent::Open {
            pid,
            tid: pid,
            fd: 3,
            dirfd: libc::AT_FDCWD,
            path: "socket:[123]".to_string(),
            emitted_ns: 1,
        }]);

        assert!(state.tree.root.children.is_empty());
        assert_eq!(state.fd_cache.lookup(pid, 3), None);
    }

    #[test]
    fn duplicated_descriptor_keeps_path_attribution() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = u32::MAX;
        state.ingest(vec![
            BpfEvent::Open {
                pid,
                tid: pid,
                fd: 3,
                dirfd: libc::AT_FDCWD,
                path: "/tmp/ncda-dup-test".to_string(),
                emitted_ns: 1,
            },
            BpfEvent::Dup {
                pid,
                tid: pid,
                old_fd: 3,
                new_fd: 4,
                emitted_ns: 2,
            },
            BpfEvent::Write {
                pid,
                tid: pid,
                fd: 4,
                bytes: 17,
                latency_ns: 11,
                emitted_ns: 3,
            },
        ]);

        let tmp = state.tree.root.children.get("tmp").unwrap();
        let file = tmp.children.get("ncda-dup-test").unwrap();
        assert_eq!(file.stats.write_bytes, 17);
        assert_eq!(state.fd_cache.lookup(pid, 4), Some("/tmp/ncda-dup-test"));
    }
}
