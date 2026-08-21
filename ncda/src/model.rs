use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Aggregated I/O statistics for a file or directory node.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NodeStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub open_ops: u64,
    pub close_ops: u64,
    /// Sum of latency_ns for all read/write ops (divide by op count for average).
    pub total_latency_ns: u64,
    /// Maximum single-operation latency observed.
    pub max_latency_ns: u64,
}

impl NodeStats {
    pub fn total_bytes(&self) -> u64 {
        self.read_bytes.saturating_add(self.write_bytes)
    }

    pub fn total_ops(&self) -> u64 {
        self.read_ops
            .saturating_add(self.write_ops)
            .saturating_add(self.open_ops)
            .saturating_add(self.close_ops)
    }

    pub fn avg_latency_ns(&self) -> u64 {
        let ops = self.read_ops.saturating_add(self.write_ops);
        self.total_latency_ns.checked_div(ops).unwrap_or(0)
    }

    pub fn accumulate(&mut self, other: &NodeStats) {
        self.read_bytes = self.read_bytes.saturating_add(other.read_bytes);
        self.write_bytes = self.write_bytes.saturating_add(other.write_bytes);
        self.read_ops = self.read_ops.saturating_add(other.read_ops);
        self.write_ops = self.write_ops.saturating_add(other.write_ops);
        self.open_ops = self.open_ops.saturating_add(other.open_ops);
        self.close_ops = self.close_ops.saturating_add(other.close_ops);
        self.total_latency_ns = self.total_latency_ns.saturating_add(other.total_latency_ns);
        self.max_latency_ns = self.max_latency_ns.max(other.max_latency_ns);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn for_operations(
        op: OpKind,
        bytes: u64,
        operations: u64,
        total_latency_ns: u64,
        max_latency_ns: u64,
    ) -> Self {
        match op {
            OpKind::Open => Self {
                open_ops: operations,
                ..Self::default()
            },
            OpKind::Read => Self {
                read_bytes: bytes,
                read_ops: operations,
                total_latency_ns,
                max_latency_ns,
                ..Self::default()
            },
            OpKind::Write => Self {
                write_bytes: bytes,
                write_ops: operations,
                total_latency_ns,
                max_latency_ns,
                ..Self::default()
            },
            OpKind::Close => Self {
                close_ops: operations,
                ..Self::default()
            },
        }
    }
}

/// Event kind for recording into the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpKind {
    Open,
    Read,
    Write,
    Close,
}

/// A node in the file/directory tree.
#[derive(Debug)]
pub struct TreeNode {
    pub name: String,
    pub is_dir: bool,
    /// Direct stats for this node (file-level I/O).
    pub stats: NodeStats,
    /// Aggregated stats including all descendants.
    pub agg_stats: NodeStats,
    /// Children keyed by basename.
    pub children: HashMap<String, TreeNode>,
    /// Per-process stats on this node.
    pub per_process: HashMap<u32, NodeStats>,
}

impl TreeNode {
    pub fn new(name: String, is_dir: bool) -> Self {
        Self {
            name,
            is_dir,
            stats: NodeStats::default(),
            agg_stats: NodeStats::default(),
            children: HashMap::new(),
            per_process: HashMap::new(),
        }
    }

    /// Get sorted children for display.
    pub fn sorted_children(&self, sort_by: SortBy, descending: bool) -> Vec<&TreeNode> {
        let mut children: Vec<&TreeNode> = self.children.values().collect();
        children.sort_by(|a, b| {
            let ord = match sort_by {
                SortBy::TotalBytes => a.agg_stats.total_bytes().cmp(&b.agg_stats.total_bytes()),
                SortBy::ReadBytes => a.agg_stats.read_bytes.cmp(&b.agg_stats.read_bytes),
                SortBy::WriteBytes => a.agg_stats.write_bytes.cmp(&b.agg_stats.write_bytes),
                SortBy::Frequency => a.agg_stats.total_ops().cmp(&b.agg_stats.total_ops()),
                SortBy::Latency => a
                    .agg_stats
                    .avg_latency_ns()
                    .cmp(&b.agg_stats.avg_latency_ns()),
                SortBy::Name => a.name.cmp(&b.name),
            };
            if descending && sort_by != SortBy::Name {
                ord.reverse()
            } else {
                ord
            }
        });
        children
    }
}

/// Sort criteria for the file list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    TotalBytes,
    ReadBytes,
    WriteBytes,
    Frequency,
    Latency,
    Name,
}

impl SortBy {
    pub fn label(&self) -> &'static str {
        match self {
            SortBy::TotalBytes => "bytes",
            SortBy::ReadBytes => "read",
            SortBy::WriteBytes => "write",
            SortBy::Frequency => "ops",
            SortBy::Latency => "latency",
            SortBy::Name => "name",
        }
    }

    pub fn next(&self) -> SortBy {
        match self {
            SortBy::TotalBytes => SortBy::ReadBytes,
            SortBy::ReadBytes => SortBy::WriteBytes,
            SortBy::WriteBytes => SortBy::Frequency,
            SortBy::Frequency => SortBy::Latency,
            SortBy::Latency => SortBy::Name,
            SortBy::Name => SortBy::TotalBytes,
        }
    }
}

/// The root of the filesystem activity tree.
pub struct FileTree {
    pub root: TreeNode,
    /// Canonical paths shared only while at least one process references them.
    active_paths: HashMap<Arc<str>, usize>,
    /// Reverse index used to remove process details without scanning the full tree.
    paths_by_process: HashMap<u32, HashSet<Arc<str>>>,
}

impl Default for FileTree {
    fn default() -> Self {
        Self::new()
    }
}

impl FileTree {
    pub fn new() -> Self {
        Self {
            root: TreeNode::new("/".into(), true),
            active_paths: HashMap::new(),
            paths_by_process: HashMap::new(),
        }
    }

    /// Record an event for the given absolute path.
    pub fn record(&mut self, path: &str, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        let delta = NodeStats::for_operations(op, bytes, 1, latency_ns, latency_ns);
        self.record_stats(path, pid, &delta);
    }

    /// Apply an already aggregated operation delta to one path.
    pub fn record_stats(&mut self, path: &str, pid: u32, delta: &NodeStats) {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return;
        }

        // Each event group contributes the same delta to every aggregate on
        // its path. Applying it while walking avoids rescanning siblings.
        let mut node = &mut self.root;
        node.agg_stats.accumulate(delta);
        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            node = node
                .children
                .entry(component.to_string())
                .or_insert_with(|| TreeNode::new(component.to_string(), !is_last));
            if !is_last {
                node.is_dir = true;
            }
            node.agg_stats.accumulate(delta);
        }

        // Direct and per-process statistics remain leaf-scoped. Index a path
        // only when this process first reaches it, keeping the steady-state
        // I/O hot path free of reverse-index hash updates.
        node.stats.accumulate(delta);
        let first_process_activity = match node.per_process.entry(pid) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().accumulate(delta);
                false
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(delta.clone());
                true
            }
        };

        if first_process_activity {
            let path = self
                .active_paths
                .get_key_value(path)
                .map(|(path, _)| Arc::clone(path))
                .unwrap_or_else(|| Arc::from(path));
            let inserted = self
                .paths_by_process
                .entry(pid)
                .or_default()
                .insert(Arc::clone(&path));
            debug_assert!(inserted, "new process/path activity must be indexed once");
            let references = self.active_paths.entry(path).or_default();
            *references = references.saturating_add(1);
        }
    }

    /// Navigate to the node at the given path components.
    pub fn get_node(&self, path: &[String]) -> Option<&TreeNode> {
        let mut node = &self.root;
        for component in path {
            node = node.children.get(component)?;
        }
        Some(node)
    }

    /// Reset all activity and release historical path/process topology.
    pub fn reset(&mut self) {
        self.root = TreeNode::new("/".into(), true);
        self.active_paths.clear();
        self.paths_by_process.clear();
    }

    /// Remove PID-scoped breakdowns when a process generation ends.
    ///
    /// A process normally touches only a small part of the observed tree. The
    /// reverse index keeps cleanup proportional to those paths instead of all
    /// paths ever seen, which is important when short-lived processes churn.
    pub fn remove_process(&mut self, pid: u32) {
        let Some(paths) = self.paths_by_process.remove(&pid) else {
            return;
        };
        for path in paths {
            if let Some(node) = find_node_mut(&mut self.root, &path) {
                node.per_process.remove(&pid);
            }
            if let std::collections::hash_map::Entry::Occupied(mut entry) =
                self.active_paths.entry(path)
            {
                if *entry.get() <= 1 {
                    entry.remove();
                } else {
                    *entry.get_mut() -= 1;
                }
            }
        }
    }
}

fn find_node_mut<'a>(root: &'a mut TreeNode, path: &str) -> Option<&'a mut TreeNode> {
    let mut node = root;
    for component in path.split('/').filter(|component| !component.is_empty()) {
        node = node.children.get_mut(component)?;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recomputed_aggregate(node: &TreeNode) -> NodeStats {
        let mut total = node.stats.clone();
        for child in node.children.values() {
            total.accumulate(&recomputed_aggregate(child));
        }
        total
    }

    fn assert_aggregate_invariants(node: &TreeNode) {
        assert_eq!(node.agg_stats, recomputed_aggregate(node), "{}", node.name);
        for child in node.children.values() {
            assert_aggregate_invariants(child);
        }
    }

    #[test]
    fn delta_propagation_preserves_fanout_aggregates() {
        let mut tree = FileTree::new();
        for index in 0..1_000 {
            tree.record(
                &format!("/fanout/dir-{index}/file"),
                index % 7,
                OpKind::Read,
                index as u64 + 1,
                index as u64,
            );
        }
        tree.record("/fanout/dir-500/file", 42, OpKind::Write, 99, 20_000);
        tree.record("/other/file", 42, OpKind::Open, 0, 0);
        tree.record("/other/file", 42, OpKind::Close, 0, 0);

        assert_aggregate_invariants(&tree.root);
        let fanout = tree.root.children.get("fanout").unwrap();
        assert_eq!(fanout.stats, NodeStats::default());
        assert_eq!(fanout.agg_stats.read_ops, 1_000);
        assert_eq!(fanout.agg_stats.write_bytes, 99);
        assert_eq!(fanout.agg_stats.max_latency_ns, 20_000);

        let leaf = &fanout.children["dir-500"].children["file"];
        assert_eq!(leaf.stats, leaf.agg_stats);
        assert_eq!(leaf.per_process[&3].read_ops, 1);
        assert_eq!(leaf.per_process[&42].write_ops, 1);
    }

    #[test]
    fn aggregated_operations_preserve_counts_and_latency() {
        let mut tree = FileTree::new();
        let delta = NodeStats::for_operations(OpKind::Read, 12_288, 3, 60, 30);
        tree.record_stats("/data/file", 7, &delta);

        let file = &tree.root.children["data"].children["file"];
        assert_eq!(file.stats.read_bytes, 12_288);
        assert_eq!(file.stats.read_ops, 3);
        assert_eq!(file.stats.total_latency_ns, 60);
        assert_eq!(file.stats.max_latency_ns, 30);
        assert_eq!(file.per_process[&7], delta);
        assert_eq!(tree.root.agg_stats, delta);
        assert_aggregate_invariants(&tree.root);
    }

    #[test]
    fn direct_and_descendant_deltas_are_not_double_counted() {
        let mut tree = FileTree::new();
        tree.record("/a", 1, OpKind::Read, 5, 7);
        tree.record("/a/b", 2, OpKind::Write, 11, 13);

        let a = tree.root.children.get("a").unwrap();
        assert!(a.is_dir);
        assert_eq!(a.stats.read_bytes, 5);
        assert_eq!(a.stats.write_bytes, 0);
        assert_eq!(a.agg_stats.read_bytes, 5);
        assert_eq!(a.agg_stats.write_bytes, 11);
        assert_eq!(a.per_process[&1].read_bytes, 5);
        assert!(!a.per_process.contains_key(&2));
        assert_eq!(a.children["b"].per_process[&2].write_bytes, 11);
        assert_aggregate_invariants(&tree.root);
    }

    #[test]
    fn process_cleanup_visits_only_indexed_paths() {
        let mut tree = FileTree::new();
        for index in 0..1_000 {
            tree.record(&format!("/history/file-{index}"), 10, OpKind::Read, 1, 1);
        }
        tree.record("/target", 20, OpKind::Write, 7, 11);
        tree.record("/target", 20, OpKind::Write, 13, 17);

        assert_eq!(tree.paths_by_process[&10].len(), 1_000);
        assert_eq!(tree.paths_by_process[&20].len(), 1);
        tree.remove_process(20);

        let target = &tree.root.children["target"];
        assert!(!target.per_process.contains_key(&20));
        assert_eq!(target.agg_stats.write_bytes, 20);
        assert_eq!(
            tree.root.children["history"].children["file-999"].per_process[&10].read_bytes,
            1
        );
        assert!(!tree.paths_by_process.contains_key(&20));
    }

    #[test]
    fn short_process_churn_does_not_scan_historical_tree() {
        let mut tree = FileTree::new();
        for index in 0..10_000 {
            tree.record(&format!("/history/file-{index}"), 1, OpKind::Read, 1, 1);
        }

        for pid in 2..=501 {
            tree.record("/churn", pid, OpKind::Write, 1, 1);
            tree.remove_process(pid);
        }

        assert_eq!(tree.paths_by_process.len(), 1);
        assert_eq!(tree.paths_by_process[&1].len(), 10_000);
        assert!(tree.root.children["churn"].per_process.is_empty());
        assert_eq!(tree.root.children["churn"].agg_stats.write_ops, 500);
    }

    #[test]
    fn process_cleanup_preserves_other_process_on_shared_path() {
        let mut tree = FileTree::new();
        tree.record("/shared", 7, OpKind::Read, 11, 13);
        tree.record("/shared", 8, OpKind::Write, 17, 19);

        tree.remove_process(7);

        let shared = &tree.root.children["shared"];
        assert!(!shared.per_process.contains_key(&7));
        assert_eq!(shared.per_process[&8].write_bytes, 17);
        assert_eq!(shared.agg_stats.read_bytes, 11);
        assert_eq!(shared.agg_stats.write_bytes, 17);
        assert_eq!(tree.active_paths["/shared"], 1);
    }

    #[test]
    fn process_cleanup_separates_reused_pid_activity() {
        let mut tree = FileTree::new();
        tree.record("/old", 7, OpKind::Read, 11, 13);
        tree.remove_process(7);
        tree.record("/new", 7, OpKind::Write, 17, 19);

        assert!(!tree.root.children["old"].per_process.contains_key(&7));
        assert_eq!(tree.root.children["old"].agg_stats.read_bytes, 11);
        assert_eq!(tree.root.children["new"].per_process[&7].write_bytes, 17);
        assert_eq!(tree.paths_by_process[&7].len(), 1);

        tree.remove_process(7);
        tree.remove_process(7);
        tree.remove_process(u32::MAX);
        assert!(!tree.root.children["new"].per_process.contains_key(&7));
        assert_eq!(tree.root.children["new"].agg_stats.write_bytes, 17);
        assert!(tree.paths_by_process.is_empty());
        assert!(tree.active_paths.is_empty());
    }

    #[test]
    fn path_aliases_cleanup_the_same_leaf() {
        let mut tree = FileTree::new();
        tree.record("//a/b/", 7, OpKind::Read, 11, 13);
        tree.record("/a/b", 7, OpKind::Write, 17, 19);

        assert_eq!(tree.paths_by_process[&7].len(), 1);
        tree.remove_process(7);

        let leaf = &tree.root.children["a"].children["b"];
        assert!(!leaf.per_process.contains_key(&7));
        assert_eq!(leaf.agg_stats.read_bytes, 11);
        assert_eq!(leaf.agg_stats.write_bytes, 17);
    }

    #[test]
    fn reset_releases_historical_topology() {
        let mut tree = FileTree::new();
        tree.record("/a/b", 7, OpKind::Read, 11, 13);
        tree.record("/a/c", 8, OpKind::Write, 17, 19);

        tree.reset();

        assert!(tree.root.children.is_empty());
        assert_eq!(tree.root.stats, NodeStats::default());
        assert_eq!(tree.root.agg_stats, NodeStats::default());
        assert!(tree.root.per_process.is_empty());
        assert!(tree.active_paths.is_empty());
        assert!(tree.paths_by_process.is_empty());
    }
}
