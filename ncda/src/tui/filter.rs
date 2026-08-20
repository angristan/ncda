use crate::model::{NodeStats, TreeNode};
use crate::process::{ProcessInfo, ProcessTable};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterQuery {
    raw: String,
    terms: Vec<FilterTerm>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterTerm {
    Any(String),
    Path(String),
    Pid(u32),
    Process(String),
    Container(String),
}

impl FilterQuery {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut terms = Vec::new();
        for token in input.split_whitespace() {
            let (field, value) = token.split_once(':').unwrap_or(("", token));
            if value.is_empty() {
                return Err(format!("missing value in filter term '{token}'"));
            }
            let value_lower = value.to_lowercase();
            let term = match field.to_ascii_lowercase().as_str() {
                "" => FilterTerm::Any(value_lower),
                "path" => FilterTerm::Path(value_lower),
                "pid" => FilterTerm::Pid(
                    value
                        .parse()
                        .map_err(|_| format!("invalid PID in filter term '{token}'"))?,
                ),
                "proc" | "process" => FilterTerm::Process(value_lower),
                "container" => FilterTerm::Container(value_lower),
                _ => return Err(format!("unknown filter field '{field}'")),
            };
            terms.push(term);
        }

        Ok(Self {
            raw: input.trim().to_string(),
            terms,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn matches_process(&self, process: &ProcessInfo) -> bool {
        self.matches("", process.pid, Some(process))
    }

    fn matches(&self, path: &str, pid: u32, process: Option<&ProcessInfo>) -> bool {
        if self.is_empty() {
            return true;
        }

        let path = path.to_lowercase();
        let pid_text = pid.to_string();
        let process_name = process
            .map(|info| info.comm.to_lowercase())
            .unwrap_or_default();
        let container = process
            .and_then(|info| info.container.as_deref())
            .map(str::to_lowercase)
            .unwrap_or_default();

        self.terms.iter().all(|term| match term {
            FilterTerm::Any(value) => {
                path.contains(value)
                    || pid_text.contains(value)
                    || process_name.contains(value)
                    || container.contains(value)
            }
            FilterTerm::Path(value) => path.contains(value),
            FilterTerm::Pid(value) => pid == *value,
            FilterTerm::Process(value) => process_name.contains(value),
            FilterTerm::Container(value) => container.contains(value),
        })
    }
}

/// Aggregate only direct per-process activity matching the query, recursively
/// including matching descendants. `per_process` is leaf-scoped, so this does
/// not double-count the node's aggregate statistics.
pub fn filtered_stats(
    node: &TreeNode,
    path: &str,
    query: &FilterQuery,
    processes: &ProcessTable,
) -> Option<NodeStats> {
    if query.is_empty() {
        return Some(node.agg_stats.clone());
    }

    let mut total = NodeStats::default();
    for (pid, stats) in &node.per_process {
        if query.matches(path, *pid, processes.processes.get(pid)) {
            total.accumulate(stats);
        }
    }

    for child in node.children.values() {
        let child_path = join_path(path, &child.name);
        if let Some(stats) = filtered_stats(child, &child_path, query, processes) {
            total.accumulate(&stats);
        }
    }

    (total.total_ops() > 0).then_some(total)
}

pub fn join_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OpKind;

    #[test]
    fn parses_combined_typed_terms() {
        let query = FilterQuery::parse("path:/var pid:42 proc:postgres container:db").unwrap();
        assert_eq!(query.raw(), "path:/var pid:42 proc:postgres container:db");
        assert_eq!(query.terms.len(), 4);
        assert!(FilterQuery::parse("pid:nope").is_err());
        assert!(FilterQuery::parse("owner:root").is_err());
    }

    #[test]
    fn matches_path_process_and_container_terms() {
        let query = FilterQuery::parse("path:log proc:post container:data").unwrap();
        let process = ProcessInfo {
            pid: 42,
            comm: "postgres".to_string(),
            container: Some("database".to_string()),
            stats: NodeStats::default(),
        };
        assert!(query.matches("/var/log/db", 42, Some(&process)));
        assert!(!query.matches("/var/lib/db", 42, Some(&process)));
    }

    #[test]
    fn recursively_aggregates_only_matching_pids() {
        let mut tree = crate::model::FileTree::new();
        tree.record("/var/a", 10, OpKind::Read, 5, 1);
        tree.record("/var/b", 20, OpKind::Read, 7, 1);
        let mut processes = ProcessTable::new();
        processes.record(10, OpKind::Read, 5, 1);
        processes.record(20, OpKind::Read, 7, 1);

        let stats = filtered_stats(
            tree.root.children.get("var").unwrap(),
            "/var",
            &FilterQuery::parse("pid:20").unwrap(),
            &processes,
        )
        .unwrap();
        assert_eq!(stats.read_bytes, 7);
    }
}
