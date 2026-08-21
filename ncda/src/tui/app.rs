use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::bpf::{BpfEvent, FdPathCache, PathResolution};
use crate::container::ContainerResolver;
use crate::model::{FileTree, NodeStats, OpKind, SortBy};
use crate::process::{ProcessSort, ProcessTable};
use crate::rate::{EventLog, RateTracker};
use crate::tui::filter::FilterQuery;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IoKey {
    pid: u32,
    fd: u32,
    op: OpKind,
}

struct IoGroup {
    key: IoKey,
    bytes: u64,
    operations: u64,
    total_latency_ns: u64,
    max_latency_ns: u64,
    observed_at: Instant,
}

impl IoGroup {
    fn new(key: IoKey, bytes: u64, latency_ns: u64, observed_at: Instant) -> Self {
        Self {
            key,
            bytes,
            operations: 1,
            total_latency_ns: latency_ns,
            max_latency_ns: latency_ns,
            observed_at,
        }
    }

    fn record(&mut self, bytes: u64, latency_ns: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.operations = self.operations.saturating_add(1);
        self.total_latency_ns = self.total_latency_ns.saturating_add(latency_ns);
        self.max_latency_ns = self.max_latency_ns.max(latency_ns);
    }

    fn stats(&self) -> NodeStats {
        NodeStats::for_operations(
            self.key.op,
            self.bytes,
            self.operations,
            self.total_latency_ns,
            self.max_latency_ns,
        )
    }
}

fn accumulate_io_group(
    groups: &mut Vec<Option<IoGroup>>,
    positions: &mut HashMap<IoKey, usize>,
    key: IoKey,
    bytes: u64,
    latency_ns: u64,
    observed_at: Instant,
) {
    if let Some(index) = positions.get(&key).copied() {
        groups[index]
            .as_mut()
            .expect("indexed I/O group must remain active")
            .record(bytes, latency_ns);
    } else {
        positions.insert(key, groups.len());
        groups.push(Some(IoGroup::new(key, bytes, latency_ns, observed_at)));
    }
}

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
        self.total_events = self
            .total_events
            .saturating_add(u64::try_from(events.len()).unwrap_or(u64::MAX));

        // Preserve every lifecycle boundary, but combine successful I/O for
        // the same descriptor between boundaries. First-seen key order keeps
        // procfs resolution deterministic while avoiding per-event tree work.
        let observed_at = Instant::now();
        let mut groups = Vec::<Option<IoGroup>>::new();
        let mut positions = HashMap::<IoKey, usize>::new();
        for event in events {
            match event {
                BpfEvent::Read {
                    pid,
                    fd,
                    bytes,
                    result,
                    latency_ns,
                    ..
                } => {
                    self.record_io_outcome(result);
                    if result > 0 {
                        accumulate_io_group(
                            &mut groups,
                            &mut positions,
                            IoKey {
                                pid,
                                fd,
                                op: OpKind::Read,
                            },
                            bytes,
                            latency_ns,
                            observed_at,
                        );
                    }
                }
                BpfEvent::Write {
                    pid,
                    fd,
                    bytes,
                    result,
                    latency_ns,
                    ..
                } => {
                    self.record_io_outcome(result);
                    if result > 0 {
                        accumulate_io_group(
                            &mut groups,
                            &mut positions,
                            IoKey {
                                pid,
                                fd,
                                op: OpKind::Write,
                            },
                            bytes,
                            latency_ns,
                            observed_at,
                        );
                    }
                }
                lifecycle => {
                    self.flush_lifecycle_groups(&lifecycle, &mut groups, &mut positions);
                    self.ingest_lifecycle(lifecycle);
                }
            }
        }
        self.flush_io_groups(&mut groups, &mut positions);
    }

    fn flush_io_groups(
        &mut self,
        groups: &mut Vec<Option<IoGroup>>,
        positions: &mut HashMap<IoKey, usize>,
    ) {
        positions.clear();
        for group in groups.drain(..).flatten() {
            self.record_io_group(group);
        }
    }

    fn flush_lifecycle_groups(
        &mut self,
        event: &BpfEvent,
        groups: &mut [Option<IoGroup>],
        positions: &mut HashMap<IoKey, usize>,
    ) {
        match event {
            BpfEvent::Open { pid, fd, .. } | BpfEvent::Close { pid, fd, .. } => {
                self.flush_fd_groups(*pid, *fd, groups, positions);
            }
            BpfEvent::Dup {
                pid,
                old_fd,
                new_fd,
                ..
            } => {
                self.flush_fd_groups(*pid, *old_fd, groups, positions);
                if old_fd != new_fd {
                    self.flush_fd_groups(*pid, *new_fd, groups, positions);
                }
            }
            BpfEvent::CloseRange {
                pid,
                first_fd,
                last_fd,
                ..
            } => {
                let keys: Vec<_> = positions
                    .keys()
                    .copied()
                    .filter(|key| key.pid == *pid && key.fd >= *first_fd && key.fd <= *last_fd)
                    .collect();
                for key in keys {
                    self.flush_io_key(key, groups, positions);
                }
            }
            BpfEvent::ProcessExec { pid, .. } | BpfEvent::ProcessExit { pid, .. } => {
                let keys: Vec<_> = positions
                    .keys()
                    .copied()
                    .filter(|key| key.pid == *pid)
                    .collect();
                for key in keys {
                    self.flush_io_key(key, groups, positions);
                }
            }
            BpfEvent::Read { .. } | BpfEvent::Write { .. } => {
                unreachable!("I/O events do not create lifecycle barriers")
            }
        }
    }

    fn flush_fd_groups(
        &mut self,
        pid: u32,
        fd: u32,
        groups: &mut [Option<IoGroup>],
        positions: &mut HashMap<IoKey, usize>,
    ) {
        for op in [OpKind::Read, OpKind::Write] {
            self.flush_io_key(IoKey { pid, fd, op }, groups, positions);
        }
    }

    fn flush_io_key(
        &mut self,
        key: IoKey,
        groups: &mut [Option<IoGroup>],
        positions: &mut HashMap<IoKey, usize>,
    ) {
        if let Some(index) = positions.remove(&key) {
            let group = groups[index]
                .take()
                .expect("indexed I/O group must remain active");
            self.record_io_group(group);
        }
    }

    fn record_io_group(&mut self, group: IoGroup) {
        let Some(path) = self.resolve_fd_path(group.key.pid, group.key.fd) else {
            // Ignored pseudo descriptors are intentionally not cached, so the
            // uncoalesced path would count each event as ignored.
            self.ignored_non_file_events = self
                .ignored_non_file_events
                .saturating_add(group.operations.saturating_sub(1));
            return;
        };
        if self.is_excluded(&path) {
            return;
        }

        let container = self.containers.resolve(group.key.pid).map(str::to_string);
        let display_path = if let Some(name) = container.as_deref() {
            format!("/[{name}]{path}")
        } else {
            path
        };
        let stats = group.stats();
        self.tree.record_stats(&display_path, group.key.pid, &stats);
        self.process_table
            .record_stats_with_context(group.key.pid, container.as_deref(), &stats);
        self.global_rate.record_at(group.observed_at, group.bytes);
        self.event_log
            .record_at(group.observed_at, display_path, group.key.pid, group.bytes);
    }

    fn ingest_lifecycle(&mut self, event: BpfEvent) {
        match event {
            BpfEvent::Open {
                pid,
                fd,
                dirfd,
                path,
                ..
            } => {
                let resolved = match self.fd_cache.resolve(pid, fd, dirfd, &path) {
                    PathResolution::Resolved(path) => path,
                    PathResolution::Unresolved(path) => {
                        self.attribution_failures = self.attribution_failures.saturating_add(1);
                        path
                    }
                    PathResolution::Ignored => {
                        self.ignored_non_file_events =
                            self.ignored_non_file_events.saturating_add(1);
                        return;
                    }
                };
                self.fd_cache.store(pid, fd, resolved.clone());
                if self.is_excluded(&resolved) {
                    return;
                }
                let display_path = self.decorate_path(pid, resolved);
                self.tree.record(&display_path, pid, OpKind::Open, 0, 0);
                self.record_process(pid, OpKind::Open, 0, 0);
            }
            BpfEvent::Close { pid, fd, .. } => {
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
                old_fd,
                new_fd,
                ..
            } => {
                let source_path = self.resolve_fd_path(pid, old_fd);
                if old_fd != new_fd {
                    self.fd_cache.on_close(pid, new_fd);
                }
                if let Some(path) = source_path {
                    self.fd_cache.store(pid, new_fd, path);
                }
            }
            BpfEvent::CloseRange {
                pid,
                first_fd,
                last_fd,
                ..
            } => {
                self.fd_cache.on_close_range(pid, first_fd, last_fd);
            }
            BpfEvent::ProcessExec { pid, .. } | BpfEvent::ProcessExit { pid, .. } => {
                self.fd_cache.on_process_reset(pid);
                self.containers.invalidate_pid(pid);
                self.process_table.remove(pid);
                self.tree.remove_process(pid);
            }
            BpfEvent::Read { .. } | BpfEvent::Write { .. } => {
                unreachable!("I/O events are accumulated before lifecycle processing")
            }
        }
    }

    fn record_io_outcome(&mut self, result: i64) {
        if result < 0 {
            self.failed_io_events = self.failed_io_events.saturating_add(1);
        } else if result == 0 {
            self.zero_byte_io_events = self.zero_byte_io_events.saturating_add(1);
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
                self.attribution_failures = self.attribution_failures.saturating_add(1);
                path
            }
            PathResolution::Ignored => {
                self.ignored_non_file_events = self.ignored_non_file_events.saturating_add(1);
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
    fn repeated_io_collapses_to_one_ordered_group() {
        let key = IoKey {
            pid: 7,
            fd: 3,
            op: OpKind::Read,
        };
        let mut groups = Vec::new();
        let mut positions = HashMap::new();
        let observed_at = Instant::now();
        for latency in 1..=4_096 {
            accumulate_io_group(
                &mut groups,
                &mut positions,
                key,
                4_096,
                latency,
                observed_at,
            );
        }

        assert_eq!(groups.len(), 1);
        let group = groups[0].as_ref().unwrap();
        assert_eq!(group.operations, 4_096);
        assert_eq!(group.bytes, 4_096 * 4_096);
        assert_eq!(group.total_latency_ns, (1..=4_096).sum());
        assert_eq!(group.max_latency_ns, 4_096);
    }

    #[test]
    fn unrelated_lifecycle_does_not_split_io_groups() {
        let key = IoKey {
            pid: 7,
            fd: 3,
            op: OpKind::Read,
        };
        let mut groups = Vec::new();
        let mut positions = HashMap::new();
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let observed_at = Instant::now();
        accumulate_io_group(&mut groups, &mut positions, key, 4_096, 10, observed_at);
        state.flush_lifecycle_groups(
            &BpfEvent::Close {
                pid: 8,
                tid: 8,
                fd: 3,
                emitted_ns: 1,
            },
            &mut groups,
            &mut positions,
        );
        accumulate_io_group(&mut groups, &mut positions, key, 4_096, 20, observed_at);

        assert_eq!(positions.len(), 1);
        assert_eq!(groups.iter().flatten().count(), 1);
        assert_eq!(groups[0].as_ref().unwrap().operations, 2);
    }

    #[test]
    fn coalescing_matches_single_event_ingestion_across_fd_replacement() {
        let pid = u32::MAX;
        let events = vec![
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 10,
                result: 10,
                latency_ns: 100,
                emitted_ns: 1,
            },
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 5,
                result: 5,
                latency_ns: 50,
                emitted_ns: 2,
            },
            BpfEvent::Write {
                pid,
                tid: pid,
                fd: 3,
                bytes: 20,
                result: 20,
                latency_ns: 200,
                emitted_ns: 3,
            },
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 0,
                result: -(libc::EIO as i64),
                latency_ns: 10,
                emitted_ns: 4,
            },
            BpfEvent::Write {
                pid,
                tid: pid,
                fd: 3,
                bytes: 0,
                result: 0,
                latency_ns: 10,
                emitted_ns: 5,
            },
            BpfEvent::Dup {
                pid,
                tid: pid,
                old_fd: 4,
                new_fd: 3,
                emitted_ns: 6,
            },
            BpfEvent::Write {
                pid,
                tid: pid,
                fd: 3,
                bytes: 7,
                result: 7,
                latency_ns: 70,
                emitted_ns: 7,
            },
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 3,
                result: 3,
                latency_ns: 30,
                emitted_ns: 8,
            },
            BpfEvent::Close {
                pid,
                tid: pid,
                fd: 3,
                emitted_ns: 9,
            },
        ];

        let mut coalesced = AppState::new(Duration::from_secs(10), Vec::new());
        let mut singles = AppState::new(Duration::from_secs(10), Vec::new());
        for state in [&mut coalesced, &mut singles] {
            state.fd_cache.store(pid, 3, "/tmp/old".to_string());
            state.fd_cache.store(pid, 4, "/tmp/new".to_string());
        }

        coalesced.ingest(events.clone());
        for event in events {
            singles.ingest(vec![event]);
        }

        assert_eq!(coalesced.total_events, 9);
        assert_eq!(coalesced.failed_io_events, 1);
        assert_eq!(coalesced.zero_byte_io_events, 1);
        assert_eq!(coalesced.fd_cache.lookup(pid, 3), None);
        let old = &coalesced.tree.root.children["tmp"].children["old"];
        let new = &coalesced.tree.root.children["tmp"].children["new"];
        assert_eq!(old.stats.read_bytes, 15);
        assert_eq!(old.stats.read_ops, 2);
        assert_eq!(old.stats.write_bytes, 20);
        assert_eq!(old.stats.write_ops, 1);
        assert_eq!(old.stats.total_latency_ns, 350);
        assert_eq!(old.stats.max_latency_ns, 200);
        assert_eq!(new.stats.read_bytes, 3);
        assert_eq!(new.stats.write_bytes, 7);
        assert_eq!(new.stats.close_ops, 1);
        assert_eq!(new.stats.total_latency_ns, 100);
        assert_eq!(new.stats.max_latency_ns, 70);

        assert_eq!(coalesced.tree.root.agg_stats, singles.tree.root.agg_stats);
        assert_eq!(
            coalesced.process_table.processes[&pid].stats,
            singles.process_table.processes[&pid].stats
        );
        assert_eq!(
            coalesced.global_rate.rate_bps(),
            singles.global_rate.rate_bps()
        );
        assert_eq!(
            coalesced.event_log.rate_for_prefix(
                "/",
                &FilterQuery::default(),
                &coalesced.process_table,
            ),
            singles
                .event_log
                .rate_for_prefix("/", &FilterQuery::default(), &singles.process_table,)
        );
    }

    #[test]
    fn coalesced_pseudo_descriptor_counts_every_ignored_event() {
        let pid = std::process::id();
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let events = (0..3)
            .map(|index| BpfEvent::Read {
                pid,
                tid: pid,
                fd: fd as u32,
                bytes: 1,
                result: 1,
                latency_ns: index + 1,
                emitted_ns: index + 1,
            })
            .collect();

        state.ingest(events);
        unsafe {
            libc::close(fd);
        }

        assert_eq!(state.ignored_non_file_events, 3);
        assert!(state.tree.root.children.is_empty());
    }

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
    fn failed_and_zero_byte_io_are_diagnostic_only() {
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

        assert!(state.tree.root.children.is_empty());
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
    fn process_exit_flushes_pending_io_before_pid_cleanup() {
        let mut state = AppState::new(Duration::from_secs(5), Vec::new());
        let pid = u32::MAX;
        state.fd_cache.store(pid, 3, "/tmp/file".to_string());
        state.ingest(vec![
            BpfEvent::Read {
                pid,
                tid: pid,
                fd: 3,
                bytes: 8,
                result: 8,
                latency_ns: 5,
                emitted_ns: 1,
            },
            BpfEvent::ProcessExit { pid, emitted_ns: 2 },
        ]);

        let file = &state.tree.root.children["tmp"].children["file"];
        assert_eq!(file.agg_stats.read_bytes, 8);
        assert!(!file.per_process.contains_key(&pid));
        assert!(!state.process_table.processes.contains_key(&pid));
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
