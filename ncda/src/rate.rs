use std::cell::RefCell;
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::process::ProcessTable;
use crate::tui::filter::FilterQuery;

// A fixed number of buckets bounds storage by active key cardinality rather
// than event volume. Sixty-four buckets keep boundary error small even for the
// short rate windows used by the TUI.
const MAX_TIME_BUCKETS: usize = 64;

/// Computes rolling bytes/sec over a bucketed time window.
pub struct RateTracker {
    window: Duration,
    bucket_width: Duration,
    state: RefCell<RateState>,
}

#[derive(Default)]
struct RateState {
    buckets: VecDeque<RateBucket>,
    window_sum: u64,
}

struct RateBucket {
    started_at: Instant,
    latest_at: Instant,
    bytes: u64,
}

impl RateTracker {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            bucket_width: bucket_width(window),
            state: RefCell::new(RateState::default()),
        }
    }

    pub fn record(&mut self, bytes: u64) {
        self.record_at(Instant::now(), bytes);
    }

    pub fn rate_bps(&self) -> f64 {
        self.rate_bps_at(Instant::now())
    }

    pub fn reset(&mut self) {
        *self.state.get_mut() = RateState::default();
    }

    fn record_at(&mut self, now: Instant, bytes: u64) {
        let state = self.state.get_mut();
        expire_rate_buckets(state, now, self.window);
        if self.window.is_zero() || bytes == 0 {
            return;
        }

        if let Some(bucket) = state.buckets.back_mut().filter(|bucket| {
            now.checked_duration_since(bucket.started_at)
                .is_some_and(|elapsed| elapsed < self.bucket_width)
        }) {
            bucket.latest_at = now;
            bucket.bytes += bytes;
        } else {
            state.buckets.push_back(RateBucket {
                started_at: now,
                latest_at: now,
                bytes,
            });
        }
        state.window_sum += bytes;
        trim_rate_buckets(state);
    }

    fn rate_bps_at(&self, now: Instant) -> f64 {
        if self.window.is_zero() {
            *self.state.borrow_mut() = RateState::default();
            return 0.0;
        }
        let mut state = self.state.borrow_mut();
        expire_rate_buckets(&mut state, now, self.window);
        state.window_sum as f64 / self.window.as_secs_f64()
    }
}

fn expire_rate_buckets(state: &mut RateState, now: Instant, window: Duration) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    while state
        .buckets
        .front()
        .is_some_and(|bucket| bucket.latest_at < cutoff)
    {
        let bucket = state.buckets.pop_front().unwrap();
        state.window_sum = state.window_sum.saturating_sub(bucket.bytes);
    }
}

fn trim_rate_buckets(state: &mut RateState) {
    while state.buckets.len() > MAX_TIME_BUCKETS {
        let bucket = state.buckets.pop_front().unwrap();
        state.window_sum = state.window_sum.saturating_sub(bucket.bytes);
    }
}

/// Bucketed recent activity for per-path rates.
///
/// Events with the same `(path, pid)` in a bucket are combined. The current
/// window is also preaggregated, so rendering scans active path/PID keys rather
/// than every event. Empty-filter prefix queries use an O(1) prefix index.
pub struct EventLog {
    window: Duration,
    bucket_width: Duration,
    state: RefCell<EventState>,
}

#[derive(Default)]
struct EventState {
    buckets: VecDeque<EventBucket>,
    activities: HashMap<ActivityKey, u64>,
    prefix_totals: HashMap<String, u64>,
    interned_paths: HashMap<String, Arc<str>>,
    path_pid_counts: HashMap<Arc<str>, usize>,
}

struct EventBucket {
    started_at: Instant,
    latest_at: Instant,
    activities: HashMap<ActivityKey, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ActivityKey {
    path: Arc<str>,
    pid: u32,
}

impl EventLog {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            bucket_width: bucket_width(window),
            state: RefCell::new(EventState::default()),
        }
    }

    pub fn record(&mut self, path: String, pid: u32, bytes: u64) {
        self.record_at(Instant::now(), path, pid, bytes);
    }

    pub fn rate_for_prefix(
        &self,
        prefix: &str,
        filter: &FilterQuery,
        processes: &ProcessTable,
    ) -> f64 {
        self.rate_for_prefix_at(Instant::now(), prefix, filter, processes)
    }

    pub fn reset(&mut self) {
        *self.state.get_mut() = EventState::default();
    }

    fn record_at(&mut self, now: Instant, path: String, pid: u32, bytes: u64) {
        let state = self.state.get_mut();
        expire_event_buckets(state, now, self.window);
        if self.window.is_zero() || bytes == 0 {
            return;
        }

        let interned_path = match state.interned_paths.entry(path) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                let path: Arc<str> = Arc::from(entry.key().as_str());
                entry.insert(Arc::clone(&path));
                path
            }
        };
        let key = ActivityKey {
            path: interned_path,
            pid,
        };

        match state.activities.entry(key.clone()) {
            Entry::Occupied(mut entry) => *entry.get_mut() += bytes,
            Entry::Vacant(entry) => {
                *state
                    .path_pid_counts
                    .entry(Arc::clone(&key.path))
                    .or_default() += 1;
                entry.insert(bytes);
            }
        }
        adjust_prefix_totals(&mut state.prefix_totals, &key.path, bytes, true);

        if let Some(bucket) = state.buckets.back_mut().filter(|bucket| {
            now.checked_duration_since(bucket.started_at)
                .is_some_and(|elapsed| elapsed < self.bucket_width)
        }) {
            bucket.latest_at = now;
            *bucket.activities.entry(key).or_default() += bytes;
        } else {
            state.buckets.push_back(EventBucket {
                started_at: now,
                latest_at: now,
                activities: HashMap::from([(key, bytes)]),
            });
        }
        trim_event_buckets(state);
    }

    fn rate_for_prefix_at(
        &self,
        now: Instant,
        prefix: &str,
        filter: &FilterQuery,
        processes: &ProcessTable,
    ) -> f64 {
        if self.window.is_zero() {
            *self.state.borrow_mut() = EventState::default();
            return 0.0;
        }

        let mut state = self.state.borrow_mut();
        expire_event_buckets(&mut state, now, self.window);
        let total_bytes = if filter.is_empty() {
            state.prefix_totals.get(prefix).copied().unwrap_or(0)
        } else {
            state
                .activities
                .iter()
                .filter(|(activity, _)| {
                    path_matches_prefix(&activity.path, prefix)
                        && filter.matches_activity(
                            &activity.path,
                            activity.pid,
                            processes.processes.get(&activity.pid),
                        )
                })
                .map(|(_, bytes)| bytes)
                .sum()
        };
        total_bytes as f64 / self.window.as_secs_f64()
    }
}

fn bucket_width(window: Duration) -> Duration {
    if window.is_zero() {
        return Duration::ZERO;
    }
    let divisor = (MAX_TIME_BUCKETS - 1) as u32;
    let nanos = window.as_nanos().div_ceil(u128::from(divisor));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64).max(Duration::from_nanos(1))
}

fn expire_event_buckets(state: &mut EventState, now: Instant, window: Duration) {
    let cutoff = now.checked_sub(window).unwrap_or(now);
    while state
        .buckets
        .front()
        .is_some_and(|bucket| bucket.latest_at < cutoff)
    {
        let bucket = state.buckets.pop_front().unwrap();
        remove_bucket(state, bucket);
    }
}

fn trim_event_buckets(state: &mut EventState) {
    while state.buckets.len() > MAX_TIME_BUCKETS {
        let bucket = state.buckets.pop_front().unwrap();
        remove_bucket(state, bucket);
    }
}

fn remove_bucket(state: &mut EventState, bucket: EventBucket) {
    for (key, bytes) in bucket.activities {
        match state.activities.entry(key.clone()) {
            Entry::Occupied(mut entry) if *entry.get() > bytes => *entry.get_mut() -= bytes,
            Entry::Occupied(entry) => {
                entry.remove();
                if let Entry::Occupied(mut count) =
                    state.path_pid_counts.entry(Arc::clone(&key.path))
                {
                    *count.get_mut() -= 1;
                    if *count.get() == 0 {
                        count.remove();
                        state.interned_paths.remove(key.path.as_ref());
                    }
                }
            }
            Entry::Vacant(_) => {}
        }
        adjust_prefix_totals(&mut state.prefix_totals, &key.path, bytes, false);
    }
}

fn adjust_prefix_totals(totals: &mut HashMap<String, u64>, path: &str, bytes: u64, add: bool) {
    for_each_path_prefix(path, |prefix| {
        if add {
            if let Some(total) = totals.get_mut(prefix) {
                *total += bytes;
            } else {
                totals.insert(prefix.to_string(), bytes);
            }
        } else if let Some(total) = totals.get_mut(prefix) {
            *total = total.saturating_sub(bytes);
            if *total == 0 {
                totals.remove(prefix);
            }
        }
    });
}

fn for_each_path_prefix(path: &str, mut visit: impl FnMut(&str)) {
    if path == "/" {
        visit(path);
        return;
    }
    visit("/");
    for (index, byte) in path.bytes().enumerate().skip(1) {
        if byte == b'/' {
            visit(&path[..index]);
        }
    }
    visit(path);
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NodeStats;
    use crate::process::ProcessInfo;

    fn process(pid: u32, comm: &str, container: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            comm: comm.to_string(),
            container: container.map(str::to_string),
            stats: NodeStats::default(),
        }
    }

    #[test]
    fn path_prefixes_stop_at_component_boundaries() {
        assert!(path_matches_prefix("/foo/bar", "/foo"));
        assert!(path_matches_prefix("/foo", "/foo"));
        assert!(!path_matches_prefix("/foobar", "/foo"));
        assert!(path_matches_prefix("/[container]/var", "/[container]"));
    }

    #[test]
    fn rates_respect_full_filters_and_prefix_boundaries() {
        let window = Duration::from_secs(5);
        let now = Instant::now();
        let mut log = EventLog::new(window);
        log.record_at(now, "/root/a".to_string(), 7, 11);
        log.record_at(now, "/root/sub/b".to_string(), 8, 13);
        log.record_at(now, "/rootish/sub/b".to_string(), 8, 101);

        let mut processes = ProcessTable::new();
        processes
            .processes
            .insert(7, process(7, "worker", Some("frontend")));
        processes
            .processes
            .insert(8, process(8, "postgres", Some("database")));

        assert_eq!(
            log.rate_for_prefix_at(
                now,
                "/root",
                &FilterQuery::parse("path:sub pid:8 proc:post container:data").unwrap(),
                &processes,
            ),
            2.6
        );
        assert_eq!(
            log.rate_for_prefix_at(
                now,
                "/root",
                &FilterQuery::parse("worker").unwrap(),
                &processes,
            ),
            2.2
        );
        assert_eq!(
            log.rate_for_prefix_at(now, "/root", &FilterQuery::default(), &processes),
            4.8
        );
    }

    #[test]
    fn queries_expire_idle_logs_and_release_interned_paths() {
        let window = Duration::from_secs(1);
        let now = Instant::now();
        let mut log = EventLog::new(window);
        log.record_at(now, "/a/b".to_string(), 7, 10);
        let expiry = now + window + log.bucket_width;

        assert_eq!(
            log.rate_for_prefix_at(expiry, "/", &FilterQuery::default(), &ProcessTable::new(),),
            0.0
        );
        let state = log.state.borrow();
        assert!(state.buckets.is_empty());
        assert!(state.activities.is_empty());
        assert!(state.prefix_totals.is_empty());
        assert!(state.interned_paths.is_empty());
    }

    #[test]
    fn repeated_events_use_bounded_aggregated_storage() {
        let window = Duration::from_secs(10);
        let now = Instant::now();
        let mut log = EventLog::new(window);
        for index in 0..100_000 {
            log.record_at(
                now + Duration::from_micros(index),
                "/busy/file".to_string(),
                7,
                1,
            );
        }

        let state = log.state.borrow();
        assert!(state.buckets.len() <= MAX_TIME_BUCKETS);
        assert!(state
            .buckets
            .iter()
            .all(|bucket| bucket.activities.len() == 1));
        assert_eq!(state.activities.len(), 1);
        assert_eq!(state.interned_paths.len(), 1);
        assert_eq!(state.prefix_totals.len(), 3);
    }

    #[test]
    fn reset_clears_rate_and_event_buckets() {
        let mut tracker = RateTracker::new(Duration::from_secs(5));
        tracker.record(10);
        tracker.reset();
        assert_eq!(tracker.rate_bps(), 0.0);
        assert!(tracker.state.borrow().buckets.is_empty());

        let mut log = EventLog::new(Duration::from_secs(5));
        log.record("/a".to_string(), 1, 10);
        log.reset();
        assert_eq!(
            log.rate_for_prefix("/", &FilterQuery::default(), &ProcessTable::new(),),
            0.0
        );
        assert!(log.state.borrow().interned_paths.is_empty());
    }

    #[test]
    fn global_tracker_expires_during_idle_queries_and_stays_bounded() {
        let window = Duration::from_secs(1);
        let now = Instant::now();
        let mut tracker = RateTracker::new(window);
        for index in 0..10_000 {
            tracker.record_at(now + Duration::from_micros(index * 100), 1);
        }
        assert!(tracker.state.borrow().buckets.len() <= MAX_TIME_BUCKETS);

        let expiry = now + Duration::from_secs(2) + tracker.bucket_width;
        assert_eq!(tracker.rate_bps_at(expiry), 0.0);
        assert!(tracker.state.borrow().buckets.is_empty());
    }

    #[test]
    fn zero_window_rates_are_zero() {
        let mut tracker = RateTracker::new(Duration::ZERO);
        tracker.record(10);
        assert_eq!(tracker.rate_bps(), 0.0);
        let mut log = EventLog::new(Duration::ZERO);
        log.record("/a".to_string(), 1, 10);
        let filter = FilterQuery::default();
        let processes = ProcessTable::new();
        assert_eq!(log.rate_for_prefix("/a", &filter, &processes), 0.0);
    }
}
