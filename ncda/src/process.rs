use std::collections::HashMap;

use crate::model::{NodeStats, OpKind};

/// Per-process I/O statistics.
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub stats: NodeStats,
}

/// Global process table tracking per-process I/O activity.
pub struct ProcessTable {
    pub processes: HashMap<u32, ProcessInfo>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn record(&mut self, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        let info = self.processes.entry(pid).or_insert_with(|| {
            let comm = read_comm(pid);
            ProcessInfo {
                pid,
                comm,
                stats: NodeStats::default(),
            }
        });
        match op {
            OpKind::Open => info.stats.open_ops += 1,
            OpKind::Read => {
                info.stats.read_bytes += bytes;
                info.stats.read_ops += 1;
                info.stats.total_latency_ns += latency_ns;
                info.stats.max_latency_ns = info.stats.max_latency_ns.max(latency_ns);
            }
            OpKind::Write => {
                info.stats.write_bytes += bytes;
                info.stats.write_ops += 1;
                info.stats.total_latency_ns += latency_ns;
                info.stats.max_latency_ns = info.stats.max_latency_ns.max(latency_ns);
            }
            OpKind::Close => info.stats.close_ops += 1,
        }
    }

    /// Get top N processes sorted by total bytes.
    pub fn top_by_bytes(&self, n: usize) -> Vec<&ProcessInfo> {
        let mut procs: Vec<&ProcessInfo> = self.processes.values().collect();
        procs.sort_by(|a, b| b.stats.total_bytes().cmp(&a.stats.total_bytes()));
        procs.truncate(n);
        procs
    }

    pub fn reset(&mut self) {
        self.processes.clear();
    }
}

/// Read the process name from /proc/PID/comm.
fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}
