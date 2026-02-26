//! Container detection and name resolution.
//!
//! Discovers running containers via `crictl` (k3s/containerd) or `docker`,
//! then matches process cgroups to known containers.
//!
//! Two cgroup formats are handled:
//!   - Format A: `…/cri-containerd-<container_id>.scope`
//!     → the 64-hex-char ID is the **container ID** from `crictl ps`.
//!   - Format B: `…kubepods-…-pod<uuid>.slice:cri-containerd:<sandbox_id>`
//!     → the 64-hex-char ID is the **pod sandbox ID** from `crictl ps`.
//!
//! At startup we run `crictl ps -o json` (one fast CLI call) and build
//! two lookup tables: container-ID → name and sandbox-ID → name.
//! Re-discovery happens every 30 s to pick up new containers.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

const REDISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// Resolves PIDs to container display names.
pub struct ContainerResolver {
    /// container ID (64 hex) → container name.
    container_names: HashMap<String, String>,
    /// pod sandbox ID (64 hex) → representative container name.
    sandbox_names: HashMap<String, String>,
    /// pid → resolved name (None = not in a container).
    pid_cache: HashMap<u32, Option<String>>,
    /// When the last discovery happened.
    last_discovery: Instant,
}

impl ContainerResolver {
    pub fn new() -> Self {
        let mut r = Self {
            container_names: HashMap::new(),
            sandbox_names: HashMap::new(),
            pid_cache: HashMap::new(),
            last_discovery: Instant::now(),
        };
        r.discover();
        r
    }

    /// Return the container display name for `pid`, or `None` if the
    /// process does not belong to a known container.
    pub fn resolve(&mut self, pid: u32) -> Option<&str> {
        if self.last_discovery.elapsed() > REDISCOVERY_INTERVAL {
            self.discover();
            self.pid_cache.clear();
        }

        if !self.pid_cache.contains_key(&pid) {
            let name = self.lookup_pid(pid);
            self.pid_cache.insert(pid, name);
        }

        self.pid_cache.get(&pid)?.as_ref().map(|s| s.as_str())
    }

    fn lookup_pid(&self, pid: u32) -> Option<String> {
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let line = cgroup.lines().next()?;

        // Extract the cgroup path (everything after hierarchy-id:controller:).
        let path = line.splitn(3, ':').nth(2).unwrap_or("");

        // --- Format A: .../cri-containerd-<ID>.scope  (or docker-/libpod-) ---
        if let Some(id) = extract_scope_id(path) {
            if let Some(name) = self.container_names.get(&id) {
                return Some(name.clone());
            }
            // Unknown container ID – use short ID.
            return Some(id[..12.min(id.len())].to_string());
        }

        // --- Format B: ...:cri-containerd:<sandbox_id> ---
        if let Some(id) = extract_colon_id(line) {
            if let Some(name) = self.sandbox_names.get(&id) {
                return Some(name.clone());
            }
            // Unknown sandbox – use short ID.
            return Some(id[..12.min(id.len())].to_string());
        }

        // --- Generic: any /docker/<ID> or /kubepods/…/<ID> ---
        if let Some(id) = extract_path_id(path) {
            if let Some(name) = self.container_names.get(&id) {
                return Some(name.clone());
            }
            return Some(id[..12.min(id.len())].to_string());
        }

        None
    }

    fn discover(&mut self) {
        self.container_names.clear();
        self.sandbox_names.clear();

        if self.discover_crictl() {
            self.last_discovery = Instant::now();
            return;
        }
        self.discover_docker();
        self.last_discovery = Instant::now();
    }

    /// Discover via `crictl ps -o json`.  Returns true on success.
    fn discover_crictl(&mut self) -> bool {
        let output = match Command::new("crictl").args(["ps", "-o", "json"]).output() {
            Ok(o) if o.status.success() => o,
            _ => return false,
        };

        let json = match std::str::from_utf8(&output.stdout) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Parse each container entry.
        // We look for: "id":"<64hex>", "name":"<str>", "podSandboxId":"<64hex>"
        // within each object in the "containers" array.
        let mut found = false;
        for entry in iter_json_array_objects(json, "containers") {
            let id = match extract_json_string(entry, "id") {
                Some(s) if is_hex64(&s) => s,
                _ => continue,
            };
            let name = match extract_json_string(entry, "name") {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let sandbox = extract_json_string(entry, "podSandboxId");

            self.container_names.insert(id, name.clone());

            if let Some(sid) = sandbox {
                if is_hex64(&sid) {
                    // First container name wins for the sandbox.
                    self.sandbox_names.entry(sid).or_insert(name);
                }
            }
            found = true;
        }

        found
    }

    /// Discover via `docker ps`.
    fn discover_docker(&mut self) {
        let output = match Command::new("docker")
            .args(["ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return,
        };

        let text = match std::str::from_utf8(&output.stdout) {
            Ok(s) => s,
            Err(_) => return,
        };

        for line in text.lines() {
            let mut parts = line.splitn(2, '\t');
            let id = match parts.next() {
                Some(s) if is_hex64(s) => s,
                _ => continue,
            };
            let name = match parts.next() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            self.container_names
                .insert(id.to_string(), name.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// cgroup ID extractors
// ---------------------------------------------------------------------------

/// Extract container ID from `…/cri-containerd-<ID>.scope` (or docker-/libpod-).
fn extract_scope_id(cgroup_path: &str) -> Option<String> {
    let segment = cgroup_path.rsplit('/').next()?;
    let rest = segment.strip_suffix(".scope")?;
    for prefix in &["cri-containerd-", "docker-", "libpod-"] {
        if let Some(id) = rest.strip_prefix(prefix) {
            if is_hex64(id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Extract sandbox/task ID from `…:cri-containerd:<ID>` pattern.
fn extract_colon_id(cgroup_line: &str) -> Option<String> {
    // The line may contain `:cri-containerd:<64hex>` at the end.
    let id = cgroup_line.rsplit(':').next()?;
    if !is_hex64(id) {
        return None;
    }
    // Verify a runtime marker precedes it.
    let prefix = cgroup_line.strip_suffix(id)?.strip_suffix(':')?;
    if prefix.ends_with("cri-containerd") || prefix.ends_with("containerd") {
        return Some(id.to_string());
    }
    None
}

/// Extract container ID from `/docker/<ID>` or `…/kubepods/…/<ID>`.
fn extract_path_id(cgroup_path: &str) -> Option<String> {
    let segments: Vec<&str> = cgroup_path.split('/').collect();
    let last = segments.last()?;
    if !is_hex64(last) {
        return None;
    }
    let has_runtime = segments.iter().any(|s| {
        *s == "docker" || *s == "kubepods" || *s == "containerd" || *s == "crio" || *s == "libpod"
    });
    if has_runtime {
        Some(last.to_string())
    } else {
        None
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (no serde dependency)
// ---------------------------------------------------------------------------

/// Find `"<key>": "<value>"` and return the string value.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let pos = json.find(&pattern)? + pattern.len();
    let rest = json[pos..].trim_start().strip_prefix(':')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Iterate over objects in a JSON array field.
///
/// Given `{"containers": [ {…}, {…} ]}`, yields each `{…}` substring
/// for the array named `array_key`.
fn iter_json_array_objects<'a>(json: &'a str, array_key: &str) -> Vec<&'a str> {
    let pattern = format!("\"{}\"", array_key);
    let start = match json.find(&pattern) {
        Some(p) => p + pattern.len(),
        None => return Vec::new(),
    };
    let rest = json[start..].trim_start();
    let rest = match rest.strip_prefix(':') {
        Some(r) => r.trim_start(),
        None => return Vec::new(),
    };
    let rest = match rest.strip_prefix('[') {
        Some(r) => r,
        None => return Vec::new(),
    };

    let mut objects = Vec::new();
    let mut depth = 0i32;
    let mut obj_start = None;

    for (i, c) in rest.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        objects.push(&rest[start..=i]);
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }

    objects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_format_cri_containerd() {
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod25d879a2_7419_43ed_9c27_142c33d5d31a.slice/cri-containerd-9ee9b6657af6e046cf844607f0ccd6b373f98023126aa62da8a60992e918daab.scope";
        assert_eq!(
            extract_scope_id(path).unwrap(),
            "9ee9b6657af6e046cf844607f0ccd6b373f98023126aa62da8a60992e918daab"
        );
    }

    #[test]
    fn scope_format_docker() {
        let path = "/system.slice/docker-abc123def456abc123def456abc123def456abc123def456abc123def456abcd.scope";
        assert_eq!(
            extract_scope_id(path).unwrap(),
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        );
    }

    #[test]
    fn colon_format_cri_containerd() {
        let line = "0::/system.slice/kubepods-besteffort-pod068b7e60_5ed7_40b9_8e99_4be4eac061b4.slice:cri-containerd:efbbd9f8e0450527a715643e2dae9646c116a33de4dd4189ec9bb79302174762";
        assert_eq!(
            extract_colon_id(line).unwrap(),
            "efbbd9f8e0450527a715643e2dae9646c116a33de4dd4189ec9bb79302174762"
        );
    }

    #[test]
    fn path_format_docker() {
        let path = "/docker/abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        assert_eq!(
            extract_path_id(path).unwrap(),
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        );
    }

    #[test]
    fn path_format_kubepods() {
        let path = "/kubepods/besteffort/pod1234/abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        assert_eq!(
            extract_path_id(path).unwrap(),
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        );
    }

    #[test]
    fn not_a_container() {
        let line = "0::/user.slice/user-1000.slice/session-1.scope";
        let path = line.splitn(3, ':').nth(2).unwrap();
        assert!(extract_scope_id(path).is_none());
        assert!(extract_colon_id(line).is_none());
        assert!(extract_path_id(path).is_none());
    }

    #[test]
    fn json_string_extraction() {
        let json = r#"{"id": "abc123", "metadata": {"name": "wordpress"}}"#;
        assert_eq!(
            extract_json_string(json, "name"),
            Some("wordpress".to_string())
        );
    }

    #[test]
    fn json_array_iteration() {
        let json = r#"{"containers": [{"id": "a", "name": "foo"}, {"id": "b", "name": "bar"}]}"#;
        let objs = iter_json_array_objects(json, "containers");
        assert_eq!(objs.len(), 2);
        assert!(objs[0].contains("foo"));
        assert!(objs[1].contains("bar"));
    }

    #[test]
    fn crictl_json_parsing() {
        let json = r#"{"containers": [
            {"id": "9ee9b6657af6e046cf844607f0ccd6b373f98023126aa62da8a60992e918daab",
             "metadata": {"name": "haproxy", "attempt": 0},
             "podSandboxId": "3618dcb97721abcdef0123456789abcdef0123456789abcdef0123456789abcd"},
            {"id": "0914b25c90b5a4343e08ac9fbe6ec8fc85c44d0e6f6cfc1990a588f367bf85ad",
             "metadata": {"name": "wordpress", "attempt": 0},
             "podSandboxId": "efbbd9f8e0450527a715643e2dae9646c116a33de4dd4189ec9bb79302174762"}
        ]}"#;
        let objs = iter_json_array_objects(json, "containers");
        assert_eq!(objs.len(), 2);
        assert_eq!(
            extract_json_string(objs[0], "name"),
            Some("haproxy".to_string())
        );
        assert_eq!(
            extract_json_string(objs[1], "name"),
            Some("wordpress".to_string())
        );
    }
}
