use std::collections::HashSet;
use std::time::Duration;

use crate::bpf::{BpfEvent, FdPathCache, PathResolution};
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
    drop_total: u64,
    drop_baseline: u64,
    pub attribution_failures: u64,
    pub ignored_non_file_events: u64,
    pub failed_io_events: u64,
    pub zero_byte_io_events: u64,
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
            drop_total: 0,
            drop_baseline: 0,
            attribution_failures: 0,
            ignored_non_file_events: 0,
            failed_io_events: 0,
            zero_byte_io_events: 0,
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
                    let resolved = match self.fd_cache.resolve(pid, fd, dirfd, &path) {
                        PathResolution::Resolved(path) => path,
                        PathResolution::Unresolved(path) => {
                            self.attribution_failures += 1;
                            path
                        }
                        PathResolution::Ignored => {
                            self.ignored_non_file_events += 1;
                            continue;
                        }
                    };
                    // Cache the process-visible path without display-only
                    // container grouping so exclusions remain component-aware.
                    self.fd_cache.store(pid, fd, resolved.clone());
                    if self.is_excluded(&resolved) {
                        continue;
                    }
                    let display_path = self.decorate_path(pid, resolved);
                    self.tree.record(&display_path, pid, OpKind::Open, 0, 0);
                    self.record_process(pid, OpKind::Open, 0, 0);
                }
                BpfEvent::Read {
                    pid,
                    tid: _,
                    fd,
                    bytes,
                    result,
                    latency_ns,
                    emitted_ns: _,
                } => {
                    self.record_io_outcome(result);
                    if let Some(path) = self.resolve_fd_path(pid, fd) {
                        if self.is_excluded(&path) {
                            continue;
                        }
                        let path = self.decorate_path(pid, path);
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
                    result,
                    latency_ns,
                    emitted_ns: _,
                } => {
                    self.record_io_outcome(result);
                    if let Some(path) = self.resolve_fd_path(pid, fd) {
                        if self.is_excluded(&path) {
                            continue;
                        }
                        let path = self.decorate_path(pid, path);
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
                    if let Some(path) = self.fd_cache.lookup(pid, fd).map(str::to_string) {
                        if !self.is_excluded(&path) {
                            let path = self.decorate_path(pid, path);
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
                    let source_path = self.resolve_fd_path(pid, old_fd);
                    if old_fd != new_fd {
                        // dup2/dup3 atomically close an existing target. Clear
                        // it even when the source is a non-file descriptor.
                        self.fd_cache.on_close(pid, new_fd);
                    }
                    if let Some(path) = source_path {
                        self.fd_cache.store(pid, new_fd, path);
                    }
                }
                BpfEvent::CloseRange {
                    pid,
                    tid: _,
                    first_fd,
                    last_fd,
                    flags: _,
                    emitted_ns: _,
                } => {
                    // Invalidating CLOSE_RANGE_CLOEXEC entries early is safe:
                    // surviving files are re-resolved on their next I/O.
                    self.fd_cache.on_close_range(pid, first_fd, last_fd);
                }
                BpfEvent::ProcessExec { pid, emitted_ns: _ }
                | BpfEvent::ProcessExit { pid, emitted_ns: _ } => {
                    self.fd_cache.on_process_reset(pid);
                    self.containers.invalidate_pid(pid);
                    self.process_table.remove(pid);
                    self.tree.remove_process(pid);
                }
            }
        }
    }

    fn record_io_outcome(&mut self, result: i64) {
        if result < 0 {
            self.failed_io_events += 1;
        } else if result == 0 {
            self.zero_byte_io_events += 1;
        }
    }

    fn record_process(&mut self, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        let container = self.containers.resolve(pid).map(str::to_string);
        self.process_table
            .record_with_context(pid, container.as_deref(), op, bytes, latency_ns);
    }

    fn resolve_fd_path(&mut self, pid: u32, fd: u32) -> Option<String> {
        if let Some(path) = self.fd_cache.lookup(pid, fd) {
            return Some(path.to_string());
        }

        let resolved = match self.fd_cache.resolve_existing(pid, fd) {
            PathResolution::Resolved(path) => path,
            PathResolution::Unresolved(path) => {
                self.attribution_failures += 1;
                path
            }
            PathResolution::Ignored => {
                self.ignored_non_file_events += 1;
                return None;
            }
        };
        self.fd_cache.store(pid, fd, resolved.clone());
        Some(resolved)
    }

    fn decorate_path(&mut self, pid: u32, path: String) -> String {
        if let Some(name) = self.containers.resolve(pid) {
            format!("/[{name}]{path}")
        } else {
            path
        }
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_prefixes.iter().any(|prefix| {
            let prefix = prefix.trim_end_matches('/');
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }

    pub fn update_drop_total(&mut self, total: u64) {
        self.drop_total = total;
        self.dropped_events = total.saturating_sub(self.drop_baseline);
    }

    pub fn reset(&mut self) {
        self.tree.reset();
        self.process_table.reset();
        self.event_log.reset();
        self.global_rate.reset();
        self.total_events = 0;
        self.drop_baseline = self.drop_total;
        self.dropped_events = 0;
        self.attribution_failures = 0;
        self.ignored_non_file_events = 0;
        self.failed_io_events = 0;
        self.zero_byte_io_events = 0;
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
    fn exclusions_match_complete_path_components() {
        let state = AppState::new(Duration::from_secs(5), vec!["/proc".to_string()]);

        assert!(state.is_excluded("/proc"));
        assert!(state.is_excluded("/proc/123/status"));
        assert!(!state.is_excluded("/procfoo/status"));
    }

    #[test]
    fn reset_uses_current_drop_total_as_baseline() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        state.update_drop_total(7);
        assert_eq!(state.dropped_events, 7);

        state.reset();
        assert_eq!(state.dropped_events, 0);
        state.update_drop_total(9);
        assert_eq!(state.dropped_events, 2);
    }

    #[test]
    fn failed_and_zero_byte_io_are_counted_as_operations() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = u32::MAX;
        state.fd_cache.store(pid, 3, "/tmp/file".to_string());
        state.ingest(vec![
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 0,
                result: -(libc::EIO as i64),
                latency_ns: 11,
                emitted_ns: 1,
            },
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 0,
                result: 0,
                latency_ns: 13,
                emitted_ns: 2,
            },
        ]);

        let file = &state.tree.root.children["tmp"].children["file"];
        assert_eq!(file.stats.read_ops, 2);
        assert_eq!(file.stats.read_bytes, 0);
        assert_eq!(file.stats.avg_latency_ns(), 12);
        assert_eq!(state.failed_io_events, 1);
        assert_eq!(state.zero_byte_io_events, 1);
    }

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
    fn dup_from_non_file_clears_existing_target() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = std::process::id();
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(event_fd >= 0);
        state.fd_cache.store(pid, 1000, "/tmp/stale".to_string());
        state.ingest(vec![BpfEvent::Dup {
            pid,
            tid: pid,
            old_fd: event_fd as u32,
            new_fd: 1000,
            emitted_ns: 1,
        }]);
        unsafe {
            libc::close(event_fd);
        }

        assert_eq!(state.fd_cache.lookup(pid, 1000), None);
    }

    #[test]
    fn process_lifecycle_event_purges_pid_scoped_state() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = u32::MAX;
        state.fd_cache.store(pid, 3, "/tmp/file".to_string());
        state.tree.record("/tmp/file", pid, OpKind::Read, 8, 1);
        state.process_table.record(pid, OpKind::Read, 8, 1);

        state.ingest(vec![BpfEvent::ProcessExec { pid, emitted_ns: 1 }]);

        assert_eq!(state.fd_cache.lookup(pid, 3), None);
        assert!(!state.process_table.processes.contains_key(&pid));
        let file = &state.tree.root.children["tmp"].children["file"];
        assert!(!file.per_process.contains_key(&pid));
        assert_eq!(file.agg_stats.read_bytes, 8);
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
                result: 17,
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
