use std::collections::HashMap;

use crate::model::{NodeStats, OpKind};

/// Per-process I/O statistics.
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub container: Option<String>,
    pub stats: NodeStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSort {
    TotalBytes,
    ReadBytes,
    WriteBytes,
    Operations,
    Latency,
    Pid,
    Name,
}

impl ProcessSort {
    pub fn next(self) -> Self {
        match self {
            Self::TotalBytes => Self::ReadBytes,
            Self::ReadBytes => Self::WriteBytes,
            Self::WriteBytes => Self::Operations,
            Self::Operations => Self::Latency,
            Self::Latency => Self::Pid,
            Self::Pid => Self::Name,
            Self::Name => Self::TotalBytes,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::TotalBytes => "bytes",
            Self::ReadBytes => "read",
            Self::WriteBytes => "write",
            Self::Operations => "ops",
            Self::Latency => "latency",
            Self::Pid => "pid",
            Self::Name => "name",
        }
    }
}

/// Global process table tracking per-process I/O activity.
pub struct ProcessTable {
    pub processes: HashMap<u32, ProcessInfo>,
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    pub fn record(&mut self, pid: u32, op: OpKind, bytes: u64, latency_ns: u64) {
        self.record_with_context(pid, None, op, bytes, latency_ns);
    }

    pub fn record_with_context(
        &mut self,
        pid: u32,
        container: Option<&str>,
        op: OpKind,
        bytes: u64,
        latency_ns: u64,
    ) {
        let info = self.processes.entry(pid).or_insert_with(|| {
            let comm = read_comm(pid);
            ProcessInfo {
                pid,
                comm,
                container: container.map(str::to_string),
                stats: NodeStats::default(),
            }
        });
        if info.container.is_none() {
            info.container = container.map(str::to_string);
        }
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

    pub fn sorted(&self, sort: ProcessSort, descending: bool) -> Vec<&ProcessInfo> {
        let mut processes: Vec<&ProcessInfo> = self.processes.values().collect();
        processes.sort_by(|a, b| {
            let order = match sort {
                ProcessSort::TotalBytes => a.stats.total_bytes().cmp(&b.stats.total_bytes()),
                ProcessSort::ReadBytes => a.stats.read_bytes.cmp(&b.stats.read_bytes),
                ProcessSort::WriteBytes => a.stats.write_bytes.cmp(&b.stats.write_bytes),
                ProcessSort::Operations => a.stats.total_ops().cmp(&b.stats.total_ops()),
                ProcessSort::Latency => a.stats.avg_latency_ns().cmp(&b.stats.avg_latency_ns()),
                ProcessSort::Pid => a.pid.cmp(&b.pid),
                ProcessSort::Name => a.comm.cmp(&b.comm),
            };
            let order = if descending { order.reverse() } else { order };
            order.then_with(|| a.pid.cmp(&b.pid))
        });
        processes
    }

    /// Get top N processes sorted by total bytes.
    pub fn top_by_bytes(&self, n: usize) -> Vec<&ProcessInfo> {
        let mut processes = self.sorted(ProcessSort::TotalBytes, true);
        processes.truncate(n);
        processes
    }

    pub fn remove(&mut self, pid: u32) {
        self.processes.remove(&pid);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_sorts_are_deterministic() {
        let mut table = ProcessTable::new();
        table.processes.insert(
            20,
            ProcessInfo {
                pid: 20,
                comm: "beta".to_string(),
                container: None,
                stats: NodeStats {
                    read_bytes: 10,
                    ..NodeStats::default()
                },
            },
        );
        table.processes.insert(
            10,
            ProcessInfo {
                pid: 10,
                comm: "alpha".to_string(),
                container: None,
                stats: NodeStats {
                    read_bytes: 10,
                    ..NodeStats::default()
                },
            },
        );

        let pids: Vec<u32> = table
            .sorted(ProcessSort::TotalBytes, true)
            .into_iter()
            .map(|process| process.pid)
            .collect();
        assert_eq!(pids, vec![10, 20]);
        assert_eq!(table.sorted(ProcessSort::Name, false)[0].pid, 10);
    }
}
