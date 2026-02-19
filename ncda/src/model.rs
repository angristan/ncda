use std::collections::HashMap;

/// Aggregated I/O statistics for a file or directory node.
#[derive(Debug, Default, Clone)]
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
        self.read_bytes + self.write_bytes
    }

    pub fn total_ops(&self) -> u64 {
        self.read_ops + self.write_ops + self.open_ops + self.close_ops
    }

    pub fn avg_latency_ns(&self) -> u64 {
        let ops = self.read_ops + self.write_ops;
        if ops == 0 {
            0
        } else {
            self.total_latency_ns / ops
        }
    }

    pub fn accumulate(&mut self, other: &NodeStats) {
        self.read_bytes += other.read_bytes;
        self.write_bytes += other.write_bytes;
        self.read_ops += other.read_ops;
        self.write_ops += other.write_ops;
        self.open_ops += other.open_ops;
        self.close_ops += other.close_ops;
        self.total_latency_ns += other.total_latency_ns;
        self.max_latency_ns = self.max_latency_ns.max(other.max_latency_ns);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Event kind for recording into the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn recompute_agg_stats(&mut self) {
        self.agg_stats = self.stats.clone();
        for child in self.children.values() {
            self.agg_stats.accumulate(&child.agg_stats);
        }
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
}

impl FileTree {
    pub fn new() -> Self {
        Self {
            root: TreeNode::new("/".into(), true),
        }
    }

    /// Record an event for the given absolute path.
    pub fn record(&mut self, path: &str, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return;
        }

        // Walk/create nodes along the path
        let mut node = &mut self.root;
        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            node = node
                .children
                .entry(component.to_string())
                .or_insert_with(|| TreeNode::new(component.to_string(), !is_last));
            // If we previously guessed it was a file but now it has children, fix it
            if !is_last {
                node.is_dir = true;
            }
        }

        // Update the leaf node's stats
        apply_stats(&mut node.stats, op, bytes, latency_ns);

        // Update per-process stats on the leaf
        let proc_stats = node.per_process.entry(pid).or_default();
        apply_stats(proc_stats, op, bytes, latency_ns);

        // Propagate aggregates up the tree
        self.propagate_agg(&components);
    }

    /// Navigate to the node at the given path components.
    pub fn get_node(&self, path: &[String]) -> Option<&TreeNode> {
        let mut node = &self.root;
        for component in path {
            node = node.children.get(component)?;
        }
        Some(node)
    }

    /// Reset all stats in the tree.
    pub fn reset(&mut self) {
        reset_node(&mut self.root);
    }

    /// Recompute agg_stats for nodes along a path (bottom-up).
    fn propagate_agg(&mut self, components: &[&str]) {
        // Collect indices of nodes along the path, then recompute bottom-up.
        // We do this by walking top-down, then recomputing at each level.
        // This is O(depth * max_children_at_level), which is fast in practice.
        fn recompute_path(node: &mut TreeNode, components: &[&str], depth: usize) {
            if depth < components.len() {
                if let Some(child) = node.children.get_mut(components[depth]) {
                    recompute_path(child, components, depth + 1);
                }
            }
            node.recompute_agg_stats();
        }
        recompute_path(&mut self.root, components, 0);
    }
}

fn apply_stats(stats: &mut NodeStats, op: OpKind, bytes: u64, latency_ns: u64) {
    match op {
        OpKind::Open => {
            stats.open_ops += 1;
        }
        OpKind::Read => {
            stats.read_bytes += bytes;
            stats.read_ops += 1;
            stats.total_latency_ns += latency_ns;
            stats.max_latency_ns = stats.max_latency_ns.max(latency_ns);
        }
        OpKind::Write => {
            stats.write_bytes += bytes;
            stats.write_ops += 1;
            stats.total_latency_ns += latency_ns;
            stats.max_latency_ns = stats.max_latency_ns.max(latency_ns);
        }
        OpKind::Close => {
            stats.close_ops += 1;
        }
    }
}

fn reset_node(node: &mut TreeNode) {
    node.stats.reset();
    node.agg_stats.reset();
    node.per_process.clear();
    for child in node.children.values_mut() {
        reset_node(child);
    }
}
